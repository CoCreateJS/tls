/********************************************************************************
 * Copyright (C) 2026 CoCreate and Contributors.
 *
 * Licensed under GNU AGPLv3.
 ********************************************************************************/

import fs from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import tls from "node:tls";
import path from "node:path";
import dns from "node:dns/promises";
import config from "@cocreate/config";
import { security, dotNotationToObject } from "@cocreate/utils";

/**
 * ACME Directory URLs for Let's Encrypt environments.
 */
const CERTIFICATES_DIRECTORY = Object.freeze({
    LETSENCRYPT_PRODUCTION: "https://acme-v02.api.letsencrypt.org/directory",
    LETSENCRYPT_STAGING: "https://acme-staging-v02.api.letsencrypt.org/directory"
});

/**
 * Default configuration state object for the certificate package.
 */
export const certificatesConfig = {
    cache: true,
    cacheTTL: 10 * 60 * 1000, // 10 minutes
    environment: "production"
};

let server = null;
let client = null;
const KEY_PATH = path.join(process.cwd(), ".certificates") + path.sep;

// In-flight request deduplication map (domain -> Promise)
const inflightRequests = new Map();
// Cache for active certificates metadata in memory
const certificatesCache = new Map();
// Cooldown tracker for failed host certificate attempts (domain -> timestamp)
const failedHosts = new Map();
const FAILED_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes

// TLS SecureContext cache for fast SNI handshakes
const secureContextCache = new Map();

// Random jitter (0 to 6 days) to stagger background renewals across instances
const RENEWAL_JITTER_DAYS = Math.floor(Math.random() * 7);

setInterval(() => {
    if (!certificatesConfig.cache) {
        if (secureContextCache.size > 0) {
            secureContextCache.clear();
        }
        return;
    }
    const now = Date.now();
    const ttl = certificatesConfig.cacheTTL || (10 * 60 * 1000);
    for (const [domain, data] of secureContextCache.entries()) {
        if (now - data.timestamp > ttl) {
            secureContextCache.delete(domain);
        }
    }
}, 60 * 1000).unref();

/**
 * Standardizes host headers by stripping ports, handling IPv6 brackets, and lowercasing.
 * @param {string} rawHost - Raw host string from HTTP/TLS headers.
 * @returns {string} Normalized domain name.
 */
function normalizeDomain(rawHost) {
    if (!rawHost || typeof rawHost !== "string") return "";
    let domain = rawHost.trim().toLowerCase();

    // Strip IPv6 port if formatted as [::1]:8080
    if (domain.startsWith("[")) {
        const closingBracket = domain.indexOf("]");
        if (closingBracket !== -1) {
            return domain.substring(1, closingBracket);
        }
    }

    // Strip standard IPv4 or hostname port
    const colonIndex = domain.indexOf(":");
    if (colonIndex !== -1) {
        domain = domain.substring(0, colonIndex);
    }

    return domain;
}

/**
 * Checks whether a given host or IP address represents a local loopback interface.
 * @param {string} rawHost - Target host or IP string.
 * @returns {boolean} True if host is localhost/loopback.
 */
export function isLocalHost(rawHost) {
    if (!rawHost || typeof rawHost !== "string") return false;
    const domain = normalizeDomain(rawHost);
    return domain === "localhost" ||
        domain === "127.0.0.1" ||
        domain === "::1" ||
        domain.endsWith(".local") ||
        domain.endsWith(".localhost");
}

/**
 * Computes directory URL based on options or configuration state.
 * @param {Object} options - Configuration options.
 * @returns {string} ACME Directory URL.
 */
function getDirectoryUrl(options = {}) {
    if (options.directoryUrl) return options.directoryUrl;

    const env = (
        options.environment ||
        options.env ||
        (options.production === true ? "production" : options.staging === true ? "staging" : certificatesConfig.environment)
    ).toLowerCase();

    return env === "production"
        ? CERTIFICATES_DIRECTORY.LETSENCRYPT_PRODUCTION
        : CERTIFICATES_DIRECTORY.LETSENCRYPT_STAGING;
}

/**
 * Loads dynamic system and database configurations for certificates.
 * @returns {Promise<Object>} Updated certificates configuration.
 */
async function loadCertificatesConfig() {
    try {
        const sysConfig = await config.get('certificates');

        let dbConfig = null;
        if (server && server.host) {
            dbConfig = await config.query({
                type: 'certificates',
                organization_id: server.organization_id,
                server: server.host,
                cluster: server.cluster_id
            });
        }

        const normalizedSys = sysConfig && sysConfig.certificates ? sysConfig : { certificates: sysConfig };
        if (normalizedSys.certificates) {
            dotNotationToObject(certificatesConfig, normalizedSys);
        }

        if (dbConfig) {
            const normalizedDb = dbConfig && dbConfig.certificates ? dbConfig : { certificates: dbConfig };
            if (normalizedDb.certificates) {
                dotNotationToObject(certificatesConfig, normalizedDb);
            }
        }
    } catch (error) {
        console.error("[@cocreate/server-tls] Failed to load certificates configuration:", error.message);
    }

    return certificatesConfig;
}

/**
 * Native ACME v2 Protocol Client supporting RFC 8555 workflows.
 */
class NativeCertificatesClient {
    constructor(options = {}) {
        this.directoryUrl = getDirectoryUrl(options);

        let accountKey = options.accountKey;
        if (typeof accountKey === "string") {
            accountKey = security.parsePrivateKey(accountKey);
        } else if (!accountKey) {
            const keyPair = security.generateKeyPair("rsa", { modulusLength: 2048 });
            accountKey = security.parsePrivateKey(keyPair.privateKey);
        }

        this.accountKey = accountKey;
        this.accountUrl = null;
        this.nonce = null;
        this.directory = null;
        this.accountInitPromise = null;

        this.jwk = security.exportJwk(this.accountKey);
        this.jwkThumbprint = security.getJwkThumbprint(this.jwk);
    }

    /**
     * Initializes the client by fetching directory endpoints and initial anti-replay nonce.
     */
    async init() {
        const res = await fetch(this.directoryUrl);
        if (!res.ok) {
            throw new Error(`Failed to fetch ACME TLS Directory (${res.status}): ${await res.text()}`);
        }
        this.directory = await res.json();
        await this.fetchNonce();
    }

    /**
     * Fetches a fresh anti-replay nonce from the ACME server.
     */
    async fetchNonce() {
        if (!this.directory || !this.directory.newNonce) {
            throw new Error("ACME directory not initialized");
        }
        const res = await fetch(this.directory.newNonce, { method: "HEAD" });
        const nonceHeader = res.headers.get("replay-nonce");
        if (!nonceHeader) {
            throw new Error("ACME server did not return replay-nonce header");
        }
        this.nonce = nonceHeader;
    }

    /**
     * Sends a JWS-signed POST request to the ACME server with automatic nonce retries.
     * @param {string} url - Destination endpoint URL.
     * @param {Object|string} payload - Request payload object or empty string.
     * @param {number} attempt - Current retry count.
     * @returns {Promise<Response>} Fetch Response object.
     */
    async postJws(url, payload, attempt = 0) {
        const MAX_NONCE_RETRIES = 3;

        if (!this.nonce) {
            await this.fetchNonce();
        }

        // Auto-register account on first authenticated call
        if (!this.accountUrl && this.directory && url !== this.directory.newAccount) {
            if (!this.accountInitPromise) {
                this.accountInitPromise = this.createAccount({ termsOfServiceAgreed: true });
            }
            await this.accountInitPromise;
        }

        const header = {
            nonce: this.nonce,
            url,
            ...(this.accountUrl ? { kid: this.accountUrl } : { jwk: this.jwk })
        };

        const body = security.createJWS(header, payload, this.accountKey);

        const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/jose+json" },
            body
        });

        const nextNonce = res.headers.get("replay-nonce");
        if (nextNonce) {
            this.nonce = nextNonce;
        }

        if (!res.ok) {
            let errorData = {};
            try {
                errorData = await res.clone().json();
            } catch {
                // Ignore parsing errors for non-JSON ACME error responses
            }

            const isBadNonce = errorData.type === "urn:ietf:params:acme:error:badNonce" ||
                errorData.type === "urn:ietf:params:certificates:error:badNonce";

            if (isBadNonce && attempt < MAX_NONCE_RETRIES) {
                await this.fetchNonce();
                return this.postJws(url, payload, attempt + 1);
            }
        }

        return res;
    }

    /**
     * Creates or registers an ACME account.
     */
    async createAccount(options = {}) {
        const payload = {
            termsOfServiceAgreed: options.termsOfServiceAgreed ?? true,
            contact: options.email ? (Array.isArray(options.email) ? options.email : [`mailto:${options.email}`]) : undefined
        };

        const res = await this.postJws(this.directory.newAccount, payload);
        if (!res.ok && res.status !== 200 && res.status !== 201) {
            throw new Error(`ACME Account Creation Failed (${res.status}): ${await res.text()}`);
        }

        this.accountUrl = res.headers.get("location");
        return await res.json();
    }

    /**
     * Initiates a new certificate order for given hostnames.
     */
    async createOrder(domains) {
        const identifiers = domains.map(domain => ({ type: "dns", value: domain }));
        const res = await this.postJws(this.directory.newOrder, { identifiers });

        if (!res.ok) {
            throw new Error(`ACME Order Creation Failed (${res.status}): ${await res.text()}`);
        }

        const orderLocation = res.headers.get("location");
        const orderData = await res.json();
        return { ...orderData, url: orderLocation };
    }

    /**
     * Retrieves authorization objects associated with an order.
     */
    async getAuthorizations(order) {
        const authorizations = [];
        for (const authUrl of order.authorizations) {
            const res = await this.postJws(authUrl, "");
            const authData = await res.json();
            authorizations.push({ ...authData, url: authUrl });
        }
        return authorizations;
    }

    /**
     * Calculates key authorization string for HTTP-01 or DNS-01 challenges.
     */
    getKeyAuthorization(token) {
        return `${token}.${this.jwkThumbprint}`;
    }

    /**
     * Notifies ACME server to perform challenge validation.
     */
    async verifyChallenge(challengeUrl) {
        const res = await this.postJws(challengeUrl, {});
        if (!res.ok) {
            throw new Error(`Failed to notify ACME challenge verification (${res.status}): ${await res.text()}`);
        }
        return await res.json();
    }

    /**
     * Polls authorization status until valid or failed.
     */
    async pollAuthorization(authUrl, maxAttempts = 15, delayMs = 2000) {
        for (let i = 0; i < maxAttempts; i++) {
            const res = await this.postJws(authUrl, "");
            const authData = await res.json();

            if (authData.status === "valid") {
                return authData;
            }

            if (authData.status === "invalid") {
                const challengeWithError = authData.challenges?.find(c => c.error);
                const errorDetail = challengeWithError
                    ? JSON.stringify(challengeWithError.error)
                    : JSON.stringify(authData);
                throw new Error(`ACME Authorization failed with status 'invalid': ${errorDetail}`);
            }

            await new Promise(resolve => setTimeout(resolve, delayMs));
        }

        throw new Error(`Timed out waiting for ACME Authorization status to reach 'valid'`);
    }

    /**
     * Polls order status until ready or valid.
     */
    async pollOrder(orderUrl, targetStatus = "ready", maxAttempts = 10, delayMs = 2000) {
        for (let i = 0; i < maxAttempts; i++) {
            const res = await this.postJws(orderUrl, "");
            const orderData = await res.json();

            if (orderData.status === targetStatus || orderData.status === "valid") {
                return orderData;
            }

            if (orderData.status === "invalid") {
                throw new Error(`ACME Order processing failed with status 'invalid': ${JSON.stringify(orderData)}`);
            }

            await new Promise(resolve => setTimeout(resolve, delayMs));
        }

        throw new Error(`Timed out waiting for ACME Order status to reach '${targetStatus}'`);
    }

    /**
     * Submits PKCS#10 CSR to finalize certificate order.
     */
    async finalizeOrder(order, domainPrivateKey, domains) {
        const csrBase64Url = security.createCSR(domainPrivateKey, domains);
        const res = await this.postJws(order.finalize, { csr: csrBase64Url });

        if (!res.ok) {
            throw new Error(`ACME Finalize Order Failed (${res.status}): ${await res.text()}`);
        }

        return await res.json();
    }

    /**
     * Downloads signed PEM certificate chain from ACME endpoint.
     */
    async downloadCertificate(certificateUrl) {
        const res = await this.postJws(certificateUrl, "");
        if (!res.ok) {
            throw new Error(`Failed to download certificate (${res.status}): ${await res.text()}`);
        }
        return await res.text();
    }
}

/**
 * Ensures a valid local self-signed certificate exists for local development or loopback testing.
 * @param {string} rawHost - Target host name (defaults to 'localhost').
 * @returns {Promise<{cert: string, key: string, domain: string}>} Certificate and key pair.
 */
export async function ensureLocalSelfSignedCert(rawHost = "localhost") {
    const domain = normalizeDomain(rawHost) || "localhost";
    const targetPath = `${KEY_PATH}${domain}/`;
    const certPath = `${targetPath}fullchain.pem`;
    const keyPath = `${targetPath}private-key.pem`;

    if (existsSync(certPath) && existsSync(keyPath)) {
        try {
            const [cert, key] = await Promise.all([
                fs.readFile(certPath, "utf8"),
                fs.readFile(keyPath, "utf8")
            ]);
            return { cert, key, domain };
        } catch (e) {
            console.error(`[@cocreate/server-tls] Error reading local self-signed cert for ${domain}:`, e.message);
        }
    }

    try {
        await fs.mkdir(targetPath, { recursive: true, mode: 0o700 });
        let key, cert;

        if (typeof security.createSelfSignedCert === "function") {
            const certData = security.createSelfSignedCert(domain);
            key = certData.key || certData.privateKey;
            cert = certData.cert || certData.certificate;
        } else {
            const keyPair = security.generateKeyPair("rsa", { modulusLength: 2048 });
            key = keyPair.privateKey;
            cert = keyPair.publicKey;
        }

        if (cert && key) {
            await Promise.all([
                fs.writeFile(certPath, cert, { mode: 0o600 }),
                fs.writeFile(keyPath, key, { mode: 0o600 })
            ]);
        }

        const expires = readCertificateExpiry(cert) || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
        certificatesCache.set(domain, { expires, organization_id: null });

        return { cert, key, domain };
    } catch (error) {
        console.error(`[@cocreate/server-tls] Failed to generate local self-signed cert for "${domain}":`, error.message);
        return { cert: null, key: null, domain };
    }
}

/**
 * Generates HTTPS options object for Node.js https/http2 server instances.
 * @param {Object} [serverInstance] - Server context instance.
 * @returns {Object} HTTPS options including default localhost keys and dynamic SNICallback handler.
 */
export function getHttpsOptions(serverInstance = null) {
    if (serverInstance) server = serverInstance;

    let defaultKey = null;
    let defaultCert = null;

    const localhostPath = `${KEY_PATH}localhost/`;
    const fullchainPath = `${localhostPath}fullchain.pem`;
    const privateKeyPath = `${localhostPath}private-key.pem`;

    if (existsSync(fullchainPath) && existsSync(privateKeyPath)) {
        try {
            defaultCert = readFileSync(fullchainPath, "utf8");
            defaultKey = readFileSync(privateKeyPath, "utf8");
        } catch (err) {
            console.error("[@cocreate/server-tls] Error reading default localhost certs synchronously:", err.message);
        }
    }

    if (!defaultCert || !defaultKey) {
        ensureLocalSelfSignedCert("localhost").catch(err => {
            console.error("[@cocreate/server-tls] Background local self-signed cert generation failed:", err.message);
        });
    }

    return {
        key: defaultKey,
        cert: defaultCert,
        SNICallback: (domainName, cb) => SNICallback(domainName, cb)
    };
}

export const createHttpsOptions = getHttpsOptions;

/**
 * Performs pre-flight DNS A/AAAA check for domain resolution.
 */
async function verifyDnsBeforeCertificates(domain) {
    try {
        const addresses = await dns.resolve4(domain);
        if (server && server.ip && addresses.length > 0) {
            return addresses.includes(server.ip);
        }
        return addresses.length > 0;
    } catch {
        return certificatesConfig.environment !== "production";
    }
}

/**
 * Parses expiration date from PEM certificate.
 */
function readCertificateExpiry(certPem) {
    try {
        if (!certPem) return null;
        const pemString = typeof certPem !== "string" ? certPem.toString() : certPem;
        const expiry = security.readCertificateExpiry(pemString);
        if (expiry) {
            const date = new Date(expiry);
            if (!isNaN(date.getTime())) return date;
        }
        return null;
    } catch {
        return null;
    }
}

/**
 * Checks if expiration timestamp is still in the future.
 */
function isValid(expires) {
    if (!expires) return false;
    const expiryDate = typeof expires === "string" || typeof expires === "number" ? new Date(expires) : expires;
    if (!expiryDate || isNaN(new Date(expiryDate).getTime())) return false;
    return new Date() < new Date(expiryDate);
}

/**
 * Determines if a certificate is due for renewal based on threshold and random jitter.
 */
function shouldRenew(expires) {
    if (!expires) return true;
    const expiryDate = typeof expires === "string" || typeof expires === "number" ? new Date(expires) : expires;
    if (!expiryDate || isNaN(new Date(expiryDate).getTime())) return true;

    const thresholdDate = new Date();
    thresholdDate.setDate(thresholdDate.getDate() + 30 - RENEWAL_JITTER_DAYS);
    return thresholdDate >= new Date(expiryDate);
}

/**
 * Validates whether certificate is active and not within expiration buffer window.
 */
function isCertificateValid(certPem, renewDaysBeforeExpiry = 30) {
    try {
        const expiryDate = readCertificateExpiry(certPem);
        if (!expiryDate) return false;
        const msPerDay = 1000 * 60 * 60 * 24;
        const daysRemaining = (expiryDate.getTime() - Date.now()) / msPerDay;

        return daysRemaining > renewDaysBeforeExpiry;
    } catch {
        return false;
    }
}

/**
 * Asynchronously loads private key and certificate chain from local disk storage.
 * @param {string} rawDomain - Target domain name.
 * @returns {Promise<{key: Buffer, cert: Buffer}>} Certificate credentials object.
 */
async function load(rawDomain) {
    const domain = normalizeDomain(rawDomain);
    const targetPath = `${KEY_PATH}${domain}/`;
    try {
        const [key, cert] = await Promise.all([
            fs.readFile(`${targetPath}private-key.pem`),
            fs.readFile(`${targetPath}fullchain.pem`)
        ]);
        return { key, cert };
    } catch (error) {
        console.error(`[@cocreate/server-tls] Error loading SSL certificates for domain "${domain}":`, error.message);
        throw error;
    }
}

/**
 * Asynchronously writes certificate credentials to local disk storage and notifies server.
 */
async function set(rawHost, expires, organization_id, hostKeyPath, cert, key) {
    const domain = normalizeDomain(rawHost);
    const targetPath = hostKeyPath || `${KEY_PATH}${domain}/`;

    if (cert && key) {
        try {
            await fs.mkdir(targetPath, { recursive: true, mode: 0o700 });
            await Promise.all([
                fs.writeFile(`${targetPath}fullchain.pem`, cert, { mode: 0o600 }),
                fs.writeFile(`${targetPath}private-key.pem`, key, { mode: 0o600 })
            ]);
        } catch (err) {
            console.error(`[@cocreate/server-tls] Failed writing certificates to disk for "${domain}":`, err.message);
        }
    }

    if (server && server.ingress && typeof server.ingress.createServer === "function") {
        try {
            server.ingress.createServer(domain);
        } catch (err) {
            console.error(`[@cocreate/server-tls] Failed calling ingress.createServer for "${domain}":`, err.message);
        }
    }

    certificatesCache.set(domain, { expires, organization_id });
    failedHosts.delete(domain);
}

/**
 * Issues ACME certificate workflow for target host.
 */
async function request(rawHost, hostPosition, hostObject, organization_id, wildcard = false) {
    const domain = normalizeDomain(rawHost);
    const hostKeyPath = `${KEY_PATH}${domain}/`;

    try {
        await fs.mkdir(hostKeyPath, { recursive: true, mode: 0o700 });

        const domains = wildcard ? [domain, `*.${domain}`] : [domain];
        const domainKeyPair = security.generateKeyPair("rsa", { modulusLength: 2048 });
        const domainPrivateKeyPem = domainKeyPair.privateKey;

        if (!client) {
            throw new Error("NativeCertificatesClient has not been initialized. Call init() first.");
        }

        const order = await client.createOrder(domains);
        const authorizations = await client.getAuthorizations(order);

        for (const auth of authorizations) {
            if (auth.status === "valid") continue;

            const httpChallenge = auth.challenges.find(c => c.type === "http-01") || auth.challenges[0];
            if (!httpChallenge) {
                throw new Error(`No available challenge handlers found for authorization on ${domain}`);
            }

            const keyAuthorization = client.getKeyAuthorization(httpChallenge.token);
            let challenge_id = "";

            if (httpChallenge.type === "http-01" && server && server.crud) {
                const httpChallengeRes = await server.crud.send({
                    method: "object.create",
                    host: domain,
                    array: "files",
                    object: {
                        "content-type": "text/plain",
                        directory: "acme-challenge",
                        host: [auth.identifier.value],
                        name: httpChallenge.token,
                        organization_id: organization_id,
                        path: "/.well-known/acme-challenge/",
                        pathname: `/.well-known/acme-challenge/${httpChallenge.token}`,
                        public: true,
                        isPublic: true,
                        src: keyAuthorization
                    },
                    organization_id
                });
                if (httpChallengeRes?.object?.[0]) {
                    challenge_id = httpChallengeRes.object[0]._id;
                }
            }

            try {
                await client.verifyChallenge(httpChallenge.url);
                await client.pollAuthorization(auth.url);
            } finally {
                if (httpChallenge.type === "http-01" && server && server.crud && challenge_id) {
                    await server.crud.send({
                        method: "object.delete",
                        host: domain,
                        array: "files",
                        object: { _id: challenge_id },
                        organization_id
                    }).catch(err => console.error("[@cocreate/server-tls] Cleanup challenge file error:", err.message));
                }
            }
        }

        const readyOrder = await client.pollOrder(order.url, "ready");
        await client.finalizeOrder(readyOrder, domainPrivateKeyPem, domains);

        const validOrder = await client.pollOrder(order.url, "valid");
        const cert = await client.downloadCertificate(validOrder.certificate);
        const expires = readCertificateExpiry(cert);

        await set(domain, expires, organization_id, hostKeyPath, cert, domainPrivateKeyPem);

        if (server && server.crud && organization_id && hostPosition !== undefined) {
            server.crud.send({
                method: "object.update",
                host: domain,
                array: "organizations",
                object: {
                    _id: organization_id,
                    [`host[${hostPosition}]`]: { ...hostObject, name: domain, cert, key: domainPrivateKeyPem, expires }
                },
                organization_id
            }).catch(err => console.error(`[@cocreate/server-tls] Database update failed for host "${domain}":`, err.message));
        }

        return true;
    } catch (error) {
        console.error(`[@cocreate/server-tls] Certificate creation failed for host "${domain}": ${error.message}`);
        return false;
    }
}

/**
 * Fetches certificate record from organization store or requests dynamic provision.
 */
async function get(rawHost, organization_id) {
    const domain = normalizeDomain(rawHost);
    const hostKeyPath = `${KEY_PATH}${domain}/`;
    let hostPosition, hostObject;

    if (!server || !server.crud) {
        console.error(`[@cocreate/server-tls] Aborting certificate lookup for host "${domain}": Server CRUD interface unavailable.`);
        return false;
    }

    let organization;
    try {
        organization = await server.crud.getOrganization({ host: domain, organization_id });
    } catch (error) {
        console.error(`[@cocreate/server-tls] CRUD error fetching organization for host "${domain}":`, error.message);
        return false;
    }

    if (organization?.object) {
        organization = Array.isArray(organization.object) ? organization.object[0] : organization.object;
    } else if (Array.isArray(organization)) {
        organization = organization[0];
    }

    if (!organization || organization.error) {
        if (organization?.error) {
            console.error(`[@cocreate/server-tls] Organization query error for host "${domain}":`, organization.error);
        }
        return false;
    }

    if (!organization_id && organization._id) {
        organization_id = organization._id;
    }

    let domainMatched = false;
    if (Array.isArray(organization.host)) {
        for (let i = 0; i < organization.host.length; i++) {
            const hostItem = organization.host[i];
            const hostName = typeof hostItem === "string" ? hostItem : hostItem?.name;

            if (hostName && normalizeDomain(hostName) === domain) {
                domainMatched = true;
                hostPosition = i;
                hostObject = typeof hostItem === "object" ? hostItem : { name: hostItem };

                const certPem = hostObject.cert;
                const keyPem = hostObject.key;

                if (certPem && keyPem) {
                    const expires = hostObject.expires || readCertificateExpiry(certPem);

                    if (isValid(expires)) {
                        await set(domain, expires, organization_id, hostKeyPath, certPem, keyPem);

                        if (shouldRenew(expires)) {
                            request(domain, hostPosition, hostObject, organization_id, false).catch(err => {
                                console.error(`[@cocreate/server-tls] Background renewal failed for "${domain}":`, err.message);
                            });
                        }
                        return true;
                    }
                }
                break;
            }
        }
    }

    if (!domainMatched) {
        return false;
    }

    const dnsValid = await verifyDnsBeforeCertificates(domain);
    if (!dnsValid) {
        return false;
    }

    return await request(domain, hostPosition, hostObject, organization_id, false);
}

/**
 * Primary check function for validating, reading, or ordering dynamic certificates.
 */
async function check(rawHost, organization_id, pathname = "") {
    if (!rawHost) return false;
    const domain = normalizeDomain(rawHost);

    if (domain === "localhost" || domain === "127.0.0.1" || isLocalHost(domain) || pathname.startsWith("/.well-known/acme-challenge/")) {
        return true;
    }

    if (certificatesCache.has(domain)) {
        const cachedCert = certificatesCache.get(domain);
        if (isValid(cachedCert.expires)) {
            return true;
        }
        certificatesCache.delete(domain);
    }

    if (failedHosts.has(domain)) {
        const lastAttempt = failedHosts.get(domain);
        if (Date.now() - lastAttempt < FAILED_COOLDOWN_MS) {
            return false;
        }
        failedHosts.delete(domain);
    }

    const hostKeyPath = `${KEY_PATH}${domain}/`;
    const fullchainPath = `${hostKeyPath}fullchain.pem`;
    const privateKeyPath = `${hostKeyPath}private-key.pem`;

    if (existsSync(fullchainPath) && existsSync(privateKeyPath)) {
        try {
            const [cert, key] = await Promise.all([
                fs.readFile(fullchainPath, "utf8"),
                fs.readFile(privateKeyPath, "utf8")
            ]);
            const expires = readCertificateExpiry(cert);

            if (isValid(expires)) {
                await set(domain, expires, organization_id, hostKeyPath, cert, key);

                if (shouldRenew(expires)) {
                    get(domain, organization_id).catch(err => {
                        console.error(`[@cocreate/server-tls] Background renewal check failed for "${domain}":`, err.message);
                    });
                }
                return true;
            }
        } catch (e) {
            console.error(`[@cocreate/server-tls] Error reading local certificate for ${domain}:`, e.message);
        }
    }

    // Deduplicate simultaneous requests for the same domain
    if (!inflightRequests.has(domain)) {
        const resolvePromise = (async () => {
            try {
                const result = await get(domain, organization_id);
                if (result) {
                    failedHosts.delete(domain);
                } else {
                    failedHosts.set(domain, Date.now());
                }
                return result;
            } catch (err) {
                console.error(`[@cocreate/server-tls] Exception during certificate resolution for "${domain}":`, err.message);
                failedHosts.set(domain, Date.now());
                throw err;
            } finally {
                inflightRequests.delete(domain);
            }
        })();

        inflightRequests.set(domain, resolvePromise);
    }

    return await inflightRequests.get(domain);
}

/**
 * Asynchronous SNI Callback handler for Node.js TLS Server.
 * @param {string} domainName - Server name indication requested by client.
 * @param {Function} cb - Standard TLS SNICallback callback function.
 */
export async function SNICallback(domainName, cb) {
    try {
        const cleanDomain = normalizeDomain(domainName);

        if (certificatesConfig.cache && secureContextCache.has(cleanDomain)) {
            const cacheEntry = secureContextCache.get(cleanDomain);
            cacheEntry.timestamp = Date.now();
            if (typeof cb === "function") return cb(null, cacheEntry.context);
            return cacheEntry.context;
        }

        const isValidDomain = await check(cleanDomain);

        if (isValidDomain) {
            const credentials = await load(cleanDomain);
            const sslContext = tls.createSecureContext(credentials);

            if (certificatesConfig.cache) {
                secureContextCache.set(cleanDomain, {
                    context: sslContext,
                    timestamp: Date.now()
                });
            }

            if (typeof cb === "function") return cb(null, sslContext);
            return sslContext;
        } else {
            const err = new Error(`[@cocreate/server-tls] Unauthorized secure request for domain: ${cleanDomain}`);
            if (typeof cb === "function") return cb(err);
            throw err;
        }
    } catch (error) {
        console.error(`[@cocreate/server-tls] Error in SNI callback for domain "${domainName}":`, error.message);
        if (typeof cb === "function") return cb(error);
        throw error;
    }
}

/**
 * Public utility to inspect certificate validity or domain status.
 */
export async function checkCertificate(input, organization_id = null, renewDaysBeforeExpiry = 30) {
    if (!input || typeof input !== "string") {
        return { valid: false, domain: null, cert: null, key: null, expires: null };
    }

    if (input.includes("-----BEGIN CERTIFICATE-----")) {
        const expires = readCertificateExpiry(input);
        const valid = isCertificateValid(input, renewDaysBeforeExpiry);
        return { valid, domain: null, cert: input, key: null, expires };
    }

    const domain = normalizeDomain(input);
    const hostKeyPath = `${KEY_PATH}${domain}/`;
    const fullchainPath = `${hostKeyPath}fullchain.pem`;
    const privateKeyPath = `${hostKeyPath}private-key.pem`;

    if (existsSync(fullchainPath) && existsSync(privateKeyPath)) {
        try {
            const [cert, key] = await Promise.all([
                fs.readFile(fullchainPath, "utf8"),
                fs.readFile(privateKeyPath, "utf8")
            ]);
            const expires = readCertificateExpiry(cert);
            const valid = isCertificateValid(cert, renewDaysBeforeExpiry);

            if (valid) {
                return { valid: true, domain, cert, key, expires };
            }
        } catch (e) {
            console.error(`[@cocreate/server-tls] Error reading certificate for ${domain}:`, e.message);
        }
    }

    const hasValidCert = await check(domain, organization_id);
    if (hasValidCert && existsSync(fullchainPath) && existsSync(privateKeyPath)) {
        try {
            const [cert, key] = await Promise.all([
                fs.readFile(fullchainPath, "utf8"),
                fs.readFile(privateKeyPath, "utf8")
            ]);
            const expires = readCertificateExpiry(cert);
            const valid = isCertificateValid(cert, renewDaysBeforeExpiry);

            return { valid, domain, cert, key, expires };
        } catch (e) {
            console.error(`[@cocreate/server-tls] Error reading certificate for ${domain}:`, e.message);
        }
    }

    return { valid: false, domain, cert: null, key: null, expires: null };
}

/**
 * Initializes the certificate manager with system settings and client instance.
 * @param {Object} serverInstance - Global application server instance.
 * @param {Object} options - Custom ACME client configuration options.
 */
export async function init(serverInstance = null, options = {}) {
    if (serverInstance) server = serverInstance;

    await loadCertificatesConfig();

    if (!client || options.accountKey || options.directoryUrl || options.environment) {
        client = new NativeCertificatesClient(options);
        await client.init();
    }

    return {
        config: certificatesConfig,
        checkCertificate,
        SNICallback,
        isLocalHost,
        ensureLocalSelfSignedCert,
        getHttpsOptions,
        createHttpsOptions
    };
}

export default {
    init
};