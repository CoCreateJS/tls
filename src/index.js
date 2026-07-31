/********************************************************************************
 * Copyright (C) 2026 CoCreate and Contributors.
 *
 * Licensed under GNU AGPLv3.
 ********************************************************************************/

import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import fs from "node:fs";
import tls from "node:tls";
import path from "node:path";
import dns from "node:dns/promises";

/**
 * Standard Let's Encrypt Directory URLs
 */
export const Certificates_DIRECTORY = {
    LETSENCRYPT_PRODUCTION: "https://acme-v02.api.letsencrypt.org/directory",
    LETSENCRYPT_STAGING: "https://acme-staging-v02.api.letsencrypt.org/directory"
};

export const directory = Certificates_DIRECTORY;

/**
 * Global environment toggle configuration.
 * Can be changed at startup or dynamically via options or env vars.
 */
export const config = {
    // Default to production unless explicitly set to staging via env or options
    isProduction: process.env.Certificates_ENV !== "staging" && process.env.Certificates_STAGING !== "true"
};

/**
 * Resolves directory URL based on options, config, or env variables
 * @param {Object} [options] - Optional override parameters
 * @returns {string} Fully qualified Certificates directory URL
 */
export function getDirectoryUrl(options = {}) {
    if (options.directoryUrl) return options.directoryUrl;
    
    const isProd = options.production ?? (options.staging !== undefined ? !options.staging : config.isProduction);
    return isProd ? Certificates_DIRECTORY.LETSENCRYPT_PRODUCTION : Certificates_DIRECTORY.LETSENCRYPT_STAGING;
}

/**
 * Converts String or Buffer into a Base64URL string (RFC 7515)
 */
function toBase64Url(input) {
    const buf = Buffer.isBuffer(input)
        ? input
        : Buffer.from(input, typeof input === "string" ? "utf8" : undefined);
    return buf.toString("base64url");
}

/**
 * Calculates RFC 7638 SHA-256 JWK Thumbprint
 */
function getJwkThumbprint(jwk) {
    const orderedJwk = jwk.kty === "RSA"
        ? { e: jwk.e, kty: jwk.kty, n: jwk.n }
        : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };

    const hash = crypto.createHash("sha256");
    hash.update(JSON.stringify(orderedJwk));
    return toBase64Url(hash.digest());
}

function derTag(tag, content) {
    let lenBytes;
    const len = content.length;

    if (len < 128) {
        lenBytes = Buffer.from([len]);
    } else if (len < 256) {
        lenBytes = Buffer.from([0x81, len]);
    } else if (len < 65536) {
        lenBytes = Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
    } else {
        lenBytes = Buffer.from([0x83, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]);
    }

    return Buffer.concat([Buffer.from([tag]), lenBytes, content]);
}

function derSequence(items) {
    return derTag(0x30, Buffer.concat(items));
}

function derSet(items) {
    return derTag(0x31, Buffer.concat(items));
}

function derOID(oidString) {
    const parts = oidString.split(".").map(Number);
    const bytes = [parts[0] * 40 + parts[1]];

    for (let i = 2; i < parts.length; i++) {
        let val = parts[i];
        const stack = [];
        stack.push(val & 0x7f);
        while ((val >>= 7) > 0) {
            stack.push((val & 0x7f) | 0x80);
        }
        bytes.push(...stack.reverse());
    }

    return derTag(0x06, Buffer.from(bytes));
}

/**
 * Generates a DER-encoded PKCS#10 Certificate Signing Request (CSR)
 * supporting single and multi-domain (SAN) configurations.
 */
export function createCSR(privateKeyInput, domains) {
    if (!domains || domains.length === 0) {
        throw new Error("At least one domain is required to generate a CSR");
    }

    const privateKey = typeof privateKeyInput === "string"
        ? crypto.createPrivateKey(privateKeyInput)
        : privateKeyInput;

    const primaryDomain = domains[0];
    const pubKeyDetails = crypto.createPublicKey(privateKey);
    const spkiDer = pubKeyDetails.export({ type: "spki", format: "der" });

    // Subject Attribute: Common Name (CN = primaryDomain)
    const subject = derSequence([
        derSet([
            derSequence([
                derOID("2.5.4.3"), // CommonName OID
                derTag(0x0c, Buffer.from(primaryDomain, "utf8")) // UTF8String
            ])
        ])
    ]);

    // Extension Request: Subject Alternative Names (SAN)
    const sanEntries = domains.map(domain => derTag(0x82, Buffer.from(domain, "utf8"))); // Context primitive [2] dNSName
    const sanExtension = derSequence([
        derOID("2.5.29.17"), // subjectAltName OID
        derTag(0x04, derSequence(sanEntries)) // OCTET STRING containing SAN Sequence
    ]);

    const extensionsSequence = derSequence([sanExtension]);
    const attributeExtensionReq = derTag(0xa0, derSequence([
        derOID("1.2.840.113549.1.9.14"), // extensionRequest OID
        derSet([extensionsSequence])
    ]));

    // CertificationRequestInfo structure
    const certReqInfo = derSequence([
        derTag(0x02, Buffer.from([0x00])), // Version 0
        subject,
        spkiDer,
        attributeExtensionReq
    ]);

    // Sign CertificationRequestInfo with Domain Private Key
    const signer = crypto.createSign("SHA256");
    signer.update(certReqInfo);
    const signature = signer.sign(privateKey);

    // Signature Algorithm OID (sha256WithRSAEncryption or ecdsa-with-SHA256)
    const isEC = privateKey.asymmetricKeyType === "ec";
    const sigAlgOid = isEC ? "1.2.840.10045.4.3.2" : "1.2.840.113549.1.1.11";
    const sigAlgorithm = derSequence([
        derOID(sigAlgOid),
        isEC ? Buffer.alloc(0) : derTag(0x05, Buffer.alloc(0)) // NULL parameters for RSA
    ]);

    // PKCS#10 CertificationRequest Sequence
    const csrDer = derSequence([
        certReqInfo,
        sigAlgorithm,
        derTag(0x03, Buffer.concat([Buffer.from([0x00]), signature])) // BIT STRING
    ]);

    return toBase64Url(csrDer);
}

/**
 * Zero-Dependency Direct Certificates Client (RFC 8555)
 */
export class NativeCertificatesClient {
    constructor(options = {}) {
        this.directoryUrl = getDirectoryUrl(options);
        
        let accountKey = options.accountKey;
        if (typeof accountKey === "string") {
            accountKey = crypto.createPrivateKey(accountKey);
        } else if (!accountKey) {
            accountKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
        }

        this.accountKey = accountKey;
        this.accountUrl = null;
        this.nonce = null;
        this.directory = null;

        const pubKey = crypto.createPublicKey(this.accountKey);
        this.jwk = pubKey.export({ format: "jwk" });
        this.jwkThumbprint = getJwkThumbprint(this.jwk);
    }

    /**
     * Initializes directory endpoints and fetches an initial anti-replay nonce
     */
    async init() {
        const res = await fetch(this.directoryUrl);
        if (!res.ok) {
            throw new Error(`Failed to fetch Certificates Directory (${res.status}): ${await res.text()}`);
        }
        this.directory = await res.json();
        await this.fetchNonce();
    }

    /**
     * Retrieves a fresh Replay-Nonce header from the Certificates server
     */
    async fetchNonce() {
        const res = await fetch(this.directory.newNonce, { method: "HEAD" });
        this.nonce = res.headers.get("replay-nonce");
    }

    /**
     * Sends an authenticated JWS payload to an Certificates endpoint
     */
    async postJws(url, payload) {
        if (!this.nonce) {
            await this.fetchNonce();
        }

        // RFC 8555 Requirement: Post-account creation requests MUST use 'kid' (accountUrl) instead of 'jwk'.
        // Automatically retrieve/verify account URL if calling any non-newAccount endpoint without accountUrl set.
        if (!this.accountUrl && this.directory && url !== this.directory.newAccount) {
            await this.createAccount({ termsOfServiceAgreed: true });
        }

        const isEC = this.accountKey.asymmetricKeyType === "ec";
        const alg = isEC ? "ES256" : "RS256";

        const header = {
            alg,
            nonce: this.nonce,
            url,
            ...(this.accountUrl ? { kid: this.accountUrl } : { jwk: this.jwk })
        };

        const protectedHeader = toBase64Url(JSON.stringify(header));
        const payloadString = payload !== "" ? toBase64Url(typeof payload === "string" ? payload : JSON.stringify(payload)) : "";

        const signInput = `${protectedHeader}.${payloadString}`;
        const signer = crypto.createSign(isEC ? "sha256" : "SHA256");
        signer.update(signInput);
        const signature = toBase64Url(signer.sign(this.accountKey));

        const body = JSON.stringify({
            protected: protectedHeader,
            payload: payloadString,
            signature
        });

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
            const errorData = await res.clone().json().catch(() => ({}));
            if (errorData.type === "urn:ietf:params:certificates:error:badNonce") {
                await this.fetchNonce();
                return this.postJws(url, payload);
            }
        }

        return res;
    }

    /**
     * Registers or logs in an Certificates Account (newAccount)
     */
    async createAccount(options = {}) {
        const payload = {
            termsOfServiceAgreed: options.termsOfServiceAgreed ?? true,
            contact: options.email ? (Array.isArray(options.email) ? options.email : [`mailto:${options.email}`]) : undefined
        };

        const res = await this.postJws(this.directory.newAccount, payload);
        if (!res.ok && res.status !== 200 && res.status !== 201) {
            throw new Error(`Certificates Account Creation Failed (${res.status}): ${await res.text()}`);
        }

        this.accountUrl = res.headers.get("location");
        return await res.json();
    }

    /**
     * Submits a new Certificate Order (newOrder)
     */
    async createOrder(domains) {
        const identifiers = domains.map(domain => ({ type: "dns", value: domain }));
        const res = await this.postJws(this.directory.newOrder, { identifiers });

        if (!res.ok) {
            throw new Error(`Certificates Order Creation Failed (${res.status}): ${await res.text()}`);
        }

        const orderLocation = res.headers.get("location");
        const orderData = await res.json();
        return { ...orderData, url: orderLocation };
    }

    /**
     * Retrieves domain authorization details and challenge tokens
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
     * Computes the HTTP-01 or DNS-01 key authorization token string
     */
    getKeyAuthorization(token) {
        return `${token}.${this.jwkThumbprint}`;
    }

    /**
     * Triggers Certificates server to verify a challenge (e.g., HTTP-01 or DNS-01)
     */
    async verifyChallenge(challengeUrl) {
        const res = await this.postJws(challengeUrl, {});
        if (!res.ok) {
            throw new Error(`Failed to notify Certificates of challenge verification (${res.status}): ${await res.text()}`);
        }
        return await res.json();
    }

    /**
     * Polls an Certificates Authorization URL until status is 'valid' or 'invalid'
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
                throw new Error(`Certificates Authorization failed with status 'invalid': ${errorDetail}`);
            }

            await new Promise(resolve => setTimeout(resolve, delayMs));
        }

        throw new Error(`Timed out waiting for Certificates Authorization status to reach 'valid'`);
    }

    /**
     * Polls the Certificates Order URL until status becomes 'ready' or 'valid'
     */
    async pollOrder(orderUrl, targetStatus = "ready", maxAttempts = 10, delayMs = 2000) {
        for (let i = 0; i < maxAttempts; i++) {
            const res = await this.postJws(orderUrl, "");
            const orderData = await res.json();

            if (orderData.status === targetStatus || orderData.status === "valid") {
                return orderData;
            }

            if (orderData.status === "invalid") {
                throw new Error(`Certificates Order processing failed with status 'invalid': ${JSON.stringify(orderData)}`);
            }

            await new Promise(resolve => setTimeout(resolve, delayMs));
        }

        throw new Error(`Timed out waiting for Certificates Order status to reach '${targetStatus}'`);
    }

    /**
     * Finalizes the order by sending the generated Certificate Signing Request (CSR)
     */
    async finalizeOrder(order, domainPrivateKey, domains) {
        const csrBase64Url = createCSR(domainPrivateKey, domains);
        const res = await this.postJws(order.finalize, { csr: csrBase64Url });

        if (!res.ok) {
            throw new Error(`Certificates Finalize Order Failed (${res.status}): ${await res.text()}`);
        }

        return await res.json();
    }

    /**
     * Downloads the final issued SSL/TLS PEM Certificate chain
     */
    async downloadCertificate(certificateUrl) {
        const res = await this.postJws(certificateUrl, "");
        if (!res.ok) {
            throw new Error(`Failed to download certificate (${res.status}): ${await res.text()}`);
        }
        return await res.text();
    }
}

// Backward-compatible alias for third-party libraries expecting `Client`
export const Client = NativeCertificatesClient;

let server = null; // Direct reference used across all module functions
const email = "ssl@cocreatejs.com";
const keyPath = path.join(process.cwd(), ".certificates") + path.sep;

let client = null;
const hosts = {};
const certificates = {};

// ==========================================
// SNI Memory Management
// ==========================================
const secureContextCache = new Map();
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

// Background Garbage Collection for inactive contexts
setInterval(() => {
    const now = Date.now();
    for (const [domain, data] of secureContextCache.entries()) {
        if (now - data.timestamp > CACHE_TTL) {
            secureContextCache.delete(domain);
        }
    }
}, 60 * 1000).unref(); // Unref prevents this timer from blocking a clean process exit

const DAYS = Math.floor(Math.random() * 7);
const HOURS = Math.floor(Math.random() * 24);
const MINUTES = Math.floor(Math.random() * 60);

/**
 * Executes a DNS lookup to ensure the domain actually points to this infrastructure
 * before requesting a certificate, preventing Certificates rate limit bans.
 */
async function verifyDnsBeforeCertificates(domain) {
    try {
        const addresses = await dns.resolve4(domain);
        // If the server knows its own IP, strictly match it. Otherwise, ensure it resolves to *something*.
        if (server && server.ip && addresses.length > 0) {
            return addresses.includes(server.ip);
        }
        return addresses.length > 0;
    } catch (err) {
        console.warn(`[@cocreate/certificates] DNS pre-flight failed for ${domain}. Skipping Let's Encrypt request.`);
        return false;
    }
}

/**
 * Extracts expiration Date from a PEM Certificate using native Node crypto.X509Certificate
 */
function readCertificateExpiry(certPem) {
    try {
        const x509 = new crypto.X509Certificate(certPem);
        return new Date(x509.validTo);
    } catch (err) {
        console.error("[@cocreate/certificates] Failed reading certificate expiry date:", err.message);
        return null;
    }
}

/**
 * Bootstraps the Certificates account keys, directories, and instantiates the
 * secure HTTPS server context, attaching it back to the parent server reference.
 * @param {Object} parentServer - Parent CoCreateServer singleton instance
 * @param {Object} [options] - Optional options ({ production: boolean, staging: boolean, directoryUrl: string })
 */
export async function init(parentServer, options = {}) {
    try {
        server = parentServer;

        // Apply top-level options if provided
        if (options.production !== undefined) config.isProduction = Boolean(options.production);
        if (options.staging !== undefined) config.isProduction = !options.staging;

        const directoryUrl = getDirectoryUrl(options);
        const modeName = directoryUrl === Certificates_DIRECTORY.LETSENCRYPT_PRODUCTION ? "PRODUCTION" : "STAGING";

        // Native folder creation with secure, owner-only read/write/execute permissions
        if (!fs.existsSync(keyPath)) {
            fs.mkdirSync(keyPath, { recursive: true, mode: 0o700 });
        }

        const accountKeyPath = `${keyPath}account.pem`;
        let accountKey = "";

        if (!fs.existsSync(accountKeyPath)) {
            const keyPair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
            accountKey = keyPair.privateKey.export({ type: "pkcs8", format: "pem" });
            fs.writeFileSync(accountKeyPath, accountKey, { mode: 0o600 });
        } else {
            accountKey = fs.readFileSync(accountKeyPath, "utf8");
        }

        client = new NativeCertificatesClient({
            directoryUrl,
            accountKey
        });

        await client.init();

        try {
            await client.createAccount({
                termsOfServiceAgreed: true,
                email
            });
            console.log(`[@cocreate/certificates] Certificates authority account initialized successfully (${modeName})!`);
        } catch (error) {
            console.error("[@cocreate/certificates] Error initializing account credentials:", error.message);
        }
    } catch (err) {
        console.error("[@cocreate/certificates] Error initializing certificate client:", err);
        throw err;
    }
}

/**
 * Interface Contract:
 * Reads SSL credentials dynamically from the secure file system.
 * @param {string} domain - Target host address
 * @returns {{key: Buffer, cert: Buffer}} Native Node TLS credential buffer
 */
export function load(domain) {
    try {
        return {
            key: fs.readFileSync(`${keyPath}${domain}/private-key.pem`),
            cert: fs.readFileSync(`${keyPath}${domain}/fullchain.pem`),
        };
    } catch (error) {
        console.error(`[@cocreate/certificates] Error loading SSL certificates for domain: ${domain}`, error);
        throw error;
    }
}

/**
 * Core SNI Handshake implementation. Resolves domains dynamically and caches TLS Contexts in RAM.
 * @param {string} domain - Incoming target SNI hostname
 * @param {Function} cb - Resolution completion callback
 */
export async function sniCallback(domain, cb) {
    try {
        // 1. Check RAM Cache First (Sub-millisecond response)
        if (secureContextCache.has(domain)) {
            const cacheEntry = secureContextCache.get(domain);
            cacheEntry.timestamp = Date.now(); // Renew TTL
            return cb(null, cacheEntry.context);
        }

        // 2. Fallback to Disk / Database / Certificates creation
        const isValidDomain = await check(domain);
        
        if (isValidDomain) {
            const credentials = load(domain);
            const sslContext = tls.createSecureContext(credentials);
            
            // 3. Store Compiled C++ Context in RAM
            secureContextCache.set(domain, {
                context: sslContext,
                timestamp: Date.now()
            });
            
            cb(null, sslContext);
        } else {
            cb(new Error(`[@cocreate/certificates] Unauthorized secure request for domain: ${domain}`));
        }
    } catch (error) {
        console.error(`[@cocreate/certificates] Error in SNI callback for domain: ${domain}`, error);
        cb(error);
    }
}

/**
 * Requests certificate generation dynamically via Certificates protocols.
 */
export async function request(host, hostPosition, hostObject, organization_id, wildcard = false) {
    try {
        const hostKeyPath = `${keyPath}${host}/`;
        
        if (!fs.existsSync(hostKeyPath)) {
            fs.mkdirSync(hostKeyPath, { recursive: true, mode: 0o700 });
        }

        const domains = wildcard ? [host, `*.${host}`] : [host];
        const domainKeyPair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
        const domainPrivateKeyPem = domainKeyPair.privateKey.export({ type: "pkcs8", format: "pem" });

        if (!client) {
            throw new Error("NativeCertificatesClient has not been initialized. Call init() first.");
        }

        const order = await client.createOrder(domains);
        const authorizations = await client.getAuthorizations(order);

        for (const auth of authorizations) {
            if (auth.status === "valid") {
                continue;
            }

            const httpChallenge = auth.challenges.find(c => c.type === "http-01") || auth.challenges[0];
            const keyAuthorization = client.getKeyAuthorization(httpChallenge.token);
            let challenge_id = "";

            if (httpChallenge.type === "http-01" && server && server.crud) {
                const httpChallengeRes = await server.crud.send({
                    method: "object.create",
                    host,
                    array: "files",
                    object: {
                        "content-type": "text/plain",
                        directory: "certificates-challenge",
                        host: [auth.identifier.value],
                        name: httpChallenge.token,
                        organization_id: organization_id,
                        path: "/.well-known/certificates-challenge/",
                        pathname: `/.well-known/certificates-challenge/${httpChallenge.token}`,
                        public: "true",
                        src: keyAuthorization
                    },
                    organization_id
                });
                if (httpChallengeRes?.object?.[0]) {
                    challenge_id = httpChallengeRes.object[0]._id;
                }
            }

            try {
                // Request validation from Certificates server
                await client.verifyChallenge(httpChallenge.url);

                // Wait for Certificates server to perform HTTP fetch and mark authorization valid
                await client.pollAuthorization(auth.url);
            } finally {
                // Cleanup challenge record ONLY after validation completes (or fails)
                if (httpChallenge.type === "http-01" && server && server.crud && challenge_id) {
                    await server.crud.send({
                        method: "object.delete",
                        host,
                        array: "files",
                        object: { _id: challenge_id },
                        organization_id
                    }).catch(err => console.error("[@cocreate/certificates] Cleanup challenge file error:", err));
                }
            }
        }

        const readyOrder = await client.pollOrder(order.url, "ready");
        await client.finalizeOrder(readyOrder, domainKeyPair.privateKey, domains);
        const validOrder = await client.pollOrder(order.url, "valid");

        const cert = await client.downloadCertificate(validOrder.certificate);
        const expires = readCertificateExpiry(cert);

        set(host, expires, organization_id, hostKeyPath, cert, domainPrivateKeyPem);
        console.log(`[@cocreate/certificates] Successfully issued SSL certificate for ${host} (Expires: ${expires})`);

        if (server && server.crud) {
            server.crud.send({
                method: "object.update",
                host,
                array: "organizations",
                object: {
                    _id: organization_id,
                    [`host[${hostPosition}]`]: { ...hostObject, name: host, cert, key: domainPrivateKeyPem, expires }
                },
                organization_id
            });
        }

        return true;
    } catch (error) {
        console.error(`[@cocreate/certificates] Certificate failed to create for ${host}!`, error);
        delete hosts[host];
        return false;
    }
}

/**
 * Resolves organization records and matches valid certificate credentials.
 */
export async function get(host, organization_id) {
    const hostKeyPath = `${keyPath}${host}/`;
    let hostPosition, hostObject;

    if (!server || !server.crud) return false;

    let organization;
    try {
        organization = await server.crud.getOrganization({ host, organization_id });
    } catch (error) {
        console.error(`[@cocreate/certificates] Failed database lookup during organization query for ${host}:`, error.message);
        return false;
    }

    // Safety check: Prevent TypeErrors if the DB yields undefined or returns an explicit error
    if (!organization || organization.error) {
        console.warn(`[@cocreate/certificates] Organization query for host "${host}" returned empty or error state.`);
        return false;
    }

    // Dynamic Resolution: If organization_id is not passed (e.g., during a blind SNI callback),
    // extract it directly from the resolved organization record to enforce correct database routing.
    if (!organization_id && organization._id) {
        organization_id = organization._id;
    }

    if (organization.host) {
        for (let i = 0; i < organization.host.length; i++) {
            if (organization.host[i].name === host) {
                hostPosition = i;
                hostObject = organization.host[i];
                
                if (organization.host[i].cert && organization.host[i].key) {
                    const expires = readCertificateExpiry(organization.host[i].cert);
                    
                    if (isValid(expires)) {
                        set(host, expires, organization_id, hostKeyPath, organization.host[i].cert, organization.host[i].key);
                        console.log(`[@cocreate/certificates] Successfully loaded certificate for ${host} from database.`);
                        return true;
                    }
                }
                break;
            }
        }
        if (!hostPosition && hostPosition !== 0) return false;
    }

    // --- PRE-FLIGHT DNS CHECK ---
    // Prevent contacting Certificates if the domain's DNS is not yet pointing to this node
    const dnsValid = await verifyDnsBeforeCertificates(host);
    if (!dnsValid) {
        return false;
    }

    return await request(host, hostPosition, hostObject, organization_id, false);
}

/**
 * Checks database registries or local systems to verify if a valid cert exists.
 */
export async function check(host, organization_id, pathname = "") {
    let hostname = host.split(":")[0];
    if (hostname === "localhost" || hostname === "127.0.0.1" || pathname.startsWith("/.well-known/certificates-challenge/")) {
        return true;
    }
    if (certificates[host]) return true;

    const hostKeyPath = `${keyPath}${host}/`;
    if (fs.existsSync(`${hostKeyPath}fullchain.pem`)) {
        let cert = fs.readFileSync(`${hostKeyPath}fullchain.pem`, "utf8");
        let expires = readCertificateExpiry(cert);
        
        if (isValid(expires)) {
            set(host, expires, organization_id);
            console.log(`[@cocreate/certificates] Successfully verified local SSL certificate for ${host}.`);
            return true;
        }
    }

    if (!hosts[host]) hosts[host] = await get(host, organization_id);
    return hosts[host];
}

/**
 * Validates if a certificate has expired based on standard and randomized drift margins.
 */
export function isValid(expires) {
    if (!expires) return false;
    const expiryDate = typeof expires === "string" || typeof expires === "number" ? new Date(expires) : expires;

    let currentDate = new Date();
    currentDate.setDate(currentDate.getDate() + DAYS);
    currentDate.setHours(currentDate.getHours() + HOURS);
    currentDate.setMinutes(currentDate.getMinutes() + MINUTES);

    return (expiryDate && currentDate < expiryDate);
}

/**
 * Writes dynamic credentials to disk securely and updates local tracking state.
 */
export function set(host, expires, organization_id, hostKeyPath, cert, key) {
    if (hostKeyPath) {
        if (!fs.existsSync(hostKeyPath)) fs.mkdirSync(hostKeyPath, { recursive: true, mode: 0o700 });
        // Enforce owner-only read/write permissions for sensitive key data
        fs.writeFileSync(`${hostKeyPath}fullchain.pem`, cert, { mode: 0o600 });
        fs.writeFileSync(`${hostKeyPath}private-key.pem`, key, { mode: 0o600 });
    }

    // Safely bypassed if Nginx is entirely removed/omitted from this deployment
    if (server && server.ingress && typeof server.ingress.createServer === "function") {
        server.ingress.createServer(host);
    }
    certificates[host] = { expires, organization_id };
}

/**
 * Checks if a PEM certificate string is valid and not expiring within renewDays threshold
 */
export function isCertificateValid(certPem, renewDaysBeforeExpiry = 30) {
    try {
        const x509 = new crypto.X509Certificate(certPem);
        const expiryDate = new Date(x509.validTo);
        const msPerDay = 1000 * 60 * 60 * 24;
        const daysRemaining = (expiryDate.getTime() - Date.now()) / msPerDay;

        return daysRemaining > renewDaysBeforeExpiry;
    } catch {
        return false;
    }
}

/**
 * Flexible check function supporting both PEM string checks and options object checks
 */
export async function checkCertificate(input, renewDaysBeforeExpiry = 30) {
    if (typeof input === "string") {
        return isCertificateValid(input, renewDaysBeforeExpiry);
    }
    return false;
}

// Default export mimics the functional API entry point
export default {
    config,
    getDirectoryUrl,
    init,
    load,
    sniCallback,
    request,
    get,
    check,
    isValid,
    set,
    NativeCertificatesClient,
    Client: NativeCertificatesClient,
    createCSR,
    isCertificateValid,
    checkCertificate,
    Certificates_DIRECTORY,
    directory: Certificates_DIRECTORY
};