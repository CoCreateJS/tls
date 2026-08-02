/********************************************************************************
 * Copyright (C) 2026 CoCreate and Contributors.
 *
 * Licensed under GNU AGPLv3.
 ********************************************************************************/

import fs from "node:fs";
import tls from "node:tls";
import path from "node:path";
import dns from "node:dns/promises";
import config from "@cocreate/config";
import { security } from "@cocreate/utils";

const Certificates_DIRECTORY = {
    LETSENCRYPT_PRODUCTION: "https://acme-v02.api.letsencrypt.org/directory",
    LETSENCRYPT_STAGING: "https://acme-staging-v02.api.letsencrypt.org/directory"
};

const defaults = {
    certificates: {
        cache: false,
        cacheTTL: 10 * 60 * 1000, // 10 minutes
        environment: (
            process.env.ENVIRONMENT || 
            process.env.NODE_ENV || 
            process.env.Certificates_ENV || 
            "production"
        ).toLowerCase()
    }
};

/**
 * Active live configuration state object.
 * Accessible via server.certificates.config
 */
export const certificatesConfig = { ...defaults.certificates };

function mergeDeep(target, ...sources) {
    if (!target || typeof target !== 'object') target = {};
    for (const source of sources) {
        if (!source || typeof source !== 'object') continue;
        for (const key of Object.keys(source)) {
            if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                if (!target[key] || typeof target[key] !== 'object') {
                    target[key] = {};
                }
                mergeDeep(target[key], source[key]);
            } else if (source[key] !== undefined) {
                target[key] = source[key];
            }
        }
    }
    return target;
}

async function loadCertificatesConfig() {
    try {
        const sysConfig = await config.get('certificates');

        let dbConfig = null;
        if (server) {
            dbConfig = await config.query({
                type: 'certificates',
                organization_id: server.organization_id,
                server: server.host,
                cluster: server.cluster_id
            });
        }

        const normalizedSys = sysConfig && sysConfig.certificates ? sysConfig : { certificates: sysConfig };
        const normalizedDb = dbConfig && dbConfig.certificates ? dbConfig : { certificates: dbConfig };

        const merged = mergeDeep({}, defaults, normalizedSys, normalizedDb);
        const resolvedConfig = merged.certificates || merged;

        Object.assign(certificatesConfig, resolvedConfig);
    } catch (error) {
        console.error("[@cocreate/certificates] Failed to load certificates configuration:", error.message);
    }

    return certificatesConfig;
}

function getDirectoryUrl(options = {}) {
    if (options.directoryUrl) return options.directoryUrl;
    
    const env = (
        options.environment || 
        options.env || 
        (options.production === true ? "production" : options.staging === true ? "staging" : certificatesConfig.environment)
    ).toLowerCase();

    const isProduction = env === "production" || env === "prod";
    return isProduction 
        ? Certificates_DIRECTORY.LETSENCRYPT_PRODUCTION 
        : Certificates_DIRECTORY.LETSENCRYPT_STAGING;
}

function createCSR(privateKeyInput, domains) {
    return security.createCSR(privateKeyInput, domains);
}

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

        this.jwk = security.exportJwk(this.accountKey);
        this.jwkThumbprint = security.getJwkThumbprint(this.jwk);
    }

    async init() {
        const res = await fetch(this.directoryUrl);
        if (!res.ok) {
            throw new Error(`Failed to fetch Certificates Directory (${res.status}): ${await res.text()}`);
        }
        this.directory = await res.json();
        await this.fetchNonce();
    }

    async fetchNonce() {
        const res = await fetch(this.directory.newNonce, { method: "HEAD" });
        this.nonce = res.headers.get("replay-nonce");
    }

    async postJws(url, payload) {
        if (!this.nonce) {
            await this.fetchNonce();
        }

        if (!this.accountUrl && this.directory && url !== this.directory.newAccount) {
            await this.createAccount({ termsOfServiceAgreed: true });
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
            const errorData = await res.clone().json().catch(() => ({}));
            if (
                errorData.type === "urn:ietf:params:acme:error:badNonce" ||
                errorData.type === "urn:ietf:params:certificates:error:badNonce"
            ) {
                await this.fetchNonce();
                return this.postJws(url, payload);
            }
        }

        return res;
    }

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

    async getAuthorizations(order) {
        const authorizations = [];
        for (const authUrl of order.authorizations) {
            const res = await this.postJws(authUrl, "");
            const authData = await res.json();
            authorizations.push({ ...authData, url: authUrl });
        }
        return authorizations;
    }

    getKeyAuthorization(token) {
        return `${token}.${this.jwkThumbprint}`;
    }

    async verifyChallenge(challengeUrl) {
        const res = await this.postJws(challengeUrl, {});
        if (!res.ok) {
            throw new Error(`Failed to notify Certificates of challenge verification (${res.status}): ${await res.text()}`);
        }
        return await res.json();
    }

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

    async finalizeOrder(order, domainPrivateKey, domains) {
        const csrBase64Url = createCSR(domainPrivateKey, domains);
        const res = await this.postJws(order.finalize, { csr: csrBase64Url });

        if (!res.ok) {
            throw new Error(`Certificates Finalize Order Failed (${res.status}): ${await res.text()}`);
        }

        return await res.json();
    }

    async downloadCertificate(certificateUrl) {
        const res = await this.postJws(certificateUrl, "");
        if (!res.ok) {
            throw new Error(`Failed to download certificate (${res.status}): ${await res.text()}`);
        }
        return await res.text();
    }
}

let server = null;
const keyPath = path.join(process.cwd(), ".certificates") + path.sep;

let client = null;
const hosts = {};
const certificates = {};

const failedHosts = new Map();
const FAILED_COOLDOWN_MS = 5 * 60 * 1000;

const secureContextCache = new Map();

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

const DAYS = Math.floor(Math.random() * 7);

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

function load(domain) {
    try {
        const cleanDomain = domain.split(":")[0].toLowerCase();
        return {
            key: fs.readFileSync(`${keyPath}${cleanDomain}/private-key.pem`),
            cert: fs.readFileSync(`${keyPath}${cleanDomain}/fullchain.pem`),
        };
    } catch (error) {
        console.error(`[@cocreate/certificates] Error loading SSL certificates for domain "${domain}":`, error);
        throw error;
    }
}

async function sniCallback(domain, cb) {
    try {
        const cleanDomain = domain.split(":")[0].toLowerCase();

        if (certificatesConfig.cache && secureContextCache.has(cleanDomain)) {
            const cacheEntry = secureContextCache.get(cleanDomain);
            cacheEntry.timestamp = Date.now();
            return cb(null, cacheEntry.context);
        }

        const isValidDomain = await check(cleanDomain);
        
        if (isValidDomain) {
            const credentials = load(cleanDomain);
            const sslContext = tls.createSecureContext(credentials);
            
            if (certificatesConfig.cache) {
                secureContextCache.set(cleanDomain, {
                    context: sslContext,
                    timestamp: Date.now()
                });
            }
            
            cb(null, sslContext);
        } else {
            cb(new Error(`[@cocreate/certificates] Unauthorized secure request for domain: ${cleanDomain}`));
        }
    } catch (error) {
        console.error(`[@cocreate/certificates] Error in SNI callback for domain "${domain}":`, error);
        cb(error);
    }
}

const SNICallback = sniCallback;

async function request(host, hostPosition, hostObject, organization_id, wildcard = false) {
    try {
        const domain = host.split(":")[0].toLowerCase();
        const hostKeyPath = `${keyPath}${domain}/`;
        
        if (!fs.existsSync(hostKeyPath)) {
            fs.mkdirSync(hostKeyPath, { recursive: true, mode: 0o700 });
        }

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
                    }).catch(err => console.error("[@cocreate/certificates] Cleanup challenge file error:", err));
                }
            }
        }

        const readyOrder = await client.pollOrder(order.url, "ready");
        await client.finalizeOrder(readyOrder, domainPrivateKeyPem, domains);
        
        const validOrder = await client.pollOrder(order.url, "valid");
        const cert = await client.downloadCertificate(validOrder.certificate);
        const expires = readCertificateExpiry(cert);

        set(domain, expires, organization_id, hostKeyPath, cert, domainPrivateKeyPem);

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
            });
        }

        return true;
    } catch (error) {
        const domain = host.split(":")[0].toLowerCase();
        console.error(`[@cocreate/certificates] Certificate creation failed for host "${domain}": ${error.message}`, error);
        delete hosts[domain];
        return false;
    }
}

async function get(host, organization_id) {
    const domain = host.split(":")[0].toLowerCase();
    const hostKeyPath = `${keyPath}${domain}/`;
    let hostPosition, hostObject;

    if (!server || !server.crud) {
        console.error(`[@cocreate/certificates] Aborting certificate lookup for host "${domain}": Server CRUD interface unavailable.`);
        return false;
    }

    let organization;
    try {
        organization = await server.crud.getOrganization({ host: domain, organization_id });
    } catch (error) {
        console.error(`[@cocreate/certificates] CRUD error fetching organization for host "${domain}":`, error);
        return false;
    }

    if (organization?.object) {
        organization = Array.isArray(organization.object) ? organization.object[0] : organization.object;
    } else if (Array.isArray(organization)) {
        organization = organization[0];
    }

    if (!organization || organization.error) {
        if (organization?.error) {
            console.error(`[@cocreate/certificates] Organization query error for host "${domain}":`, organization.error);
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

            if (hostName && hostName.toLowerCase() === domain) {
                domainMatched = true;
                hostPosition = i;
                hostObject = typeof hostItem === "object" ? hostItem : { name: hostItem };
                
                const certPem = hostObject.cert;
                const keyPem = hostObject.key;

                if (certPem && keyPem) {
                    const expires = hostObject.expires || readCertificateExpiry(certPem);
                    
                    if (isValid(expires)) {
                        set(domain, expires, organization_id, hostKeyPath, certPem, keyPem);
                        
                        if (shouldRenew(expires)) {
                            request(domain, hostPosition, hostObject, organization_id, false).catch(err => {
                                console.error(`[@cocreate/certificates] Background renewal failed for "${domain}":`, err.message);
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

async function check(host, organization_id, pathname = "") {
    if (!host) return false;
    const domain = host.split(":")[0].toLowerCase();

    if (domain === "localhost" || domain === "127.0.0.1" || pathname.startsWith("/.well-known/acme-challenge/")) {
        return true;
    }

    if (certificates[domain]) {
        if (isValid(certificates[domain].expires)) {
            return true;
        }
        delete certificates[domain];
    }

    if (failedHosts.has(domain)) {
        const lastAttempt = failedHosts.get(domain);
        if (Date.now() - lastAttempt < FAILED_COOLDOWN_MS) {
            return false;
        }
        failedHosts.delete(domain);
    }

    const hostKeyPath = `${keyPath}${domain}/`;
    const fullchainPath = `${hostKeyPath}fullchain.pem`;
    const privateKeyPath = `${hostKeyPath}private-key.pem`;

    if (fs.existsSync(fullchainPath) && fs.existsSync(privateKeyPath)) {
        try {
            let cert = fs.readFileSync(fullchainPath, "utf8");
            let key = fs.readFileSync(privateKeyPath, "utf8");
            let expires = readCertificateExpiry(cert);
            
            if (isValid(expires)) {
                set(domain, expires, organization_id, hostKeyPath, cert, key);
                
                if (shouldRenew(expires)) {
                    get(domain, organization_id).catch(err => {
                        console.error(`[@cocreate/certificates] Background renewal check failed for "${domain}":`, err.message);
                    });
                }
                return true;
            }
        } catch (e) {
            console.error(`[@cocreate/certificates] Error reading local certificate for ${domain}:`, e.message);
        }
    }

    if (!hosts[domain]) {
        hosts[domain] = (async () => {
            try {
                const result = await get(domain, organization_id);
                if (result) {
                    failedHosts.delete(domain);
                } else {
                    failedHosts.set(domain, Date.now());
                }
                return result;
            } catch (err) {
                console.error(`[@cocreate/certificates] Exception during certificate resolution for "${domain}":`, err.message);
                failedHosts.set(domain, Date.now());
                throw err;
            } finally {
                delete hosts[domain];
            }
        })();
    }

    return await hosts[domain];
}

function isValid(expires) {
    if (!expires) return false;
    const expiryDate = typeof expires === "string" || typeof expires === "number" ? new Date(expires) : expires;
    if (!expiryDate || isNaN(new Date(expiryDate).getTime())) return false;
    return new Date() < new Date(expiryDate);
}

function shouldRenew(expires) {
    if (!expires) return true;
    const expiryDate = typeof expires === "string" || typeof expires === "number" ? new Date(expires) : expires;
    if (!expiryDate || isNaN(new Date(expiryDate).getTime())) return true;

    const thresholdDate = new Date();
    thresholdDate.setDate(thresholdDate.getDate() + 30 - DAYS);
    return thresholdDate >= new Date(expiryDate);
}

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

function set(host, expires, organization_id, hostKeyPath, cert, key) {
    const domain = host.split(":")[0].toLowerCase();
    const targetPath = hostKeyPath || `${keyPath}${domain}/`;
    if (cert && key) {
        if (!fs.existsSync(targetPath)) {
            fs.mkdirSync(targetPath, { recursive: true, mode: 0o700 });
        }
        fs.writeFileSync(`${targetPath}fullchain.pem`, cert, { mode: 0o600 });
        fs.writeFileSync(`${targetPath}private-key.pem`, key, { mode: 0o600 });
    }

    if (server && server.ingress && typeof server.ingress.createServer === "function") {
        server.ingress.createServer(domain);
    }
    certificates[domain] = { expires, organization_id };
    failedHosts.delete(domain);
}

export async function checkCertificate(input, organization_id = null, renewDaysBeforeExpiry = 30) {
    if (!input || typeof input !== "string") {
        return { valid: false, domain: null, cert: null, key: null, expires: null };
    }

    if (input.includes("-----BEGIN CERTIFICATE-----")) {
        const expires = readCertificateExpiry(input);
        const valid = isCertificateValid(input, renewDaysBeforeExpiry);
        return { valid, domain: null, cert: input, key: null, expires };
    }

    const domain = input.split(":")[0].toLowerCase();
    const hostKeyPath = `${keyPath}${domain}/`;
    const fullchainPath = `${hostKeyPath}fullchain.pem`;
    const privateKeyPath = `${hostKeyPath}private-key.pem`;

    if (fs.existsSync(fullchainPath) && fs.existsSync(privateKeyPath)) {
        try {
            const cert = fs.readFileSync(fullchainPath, "utf8");
            const key = fs.readFileSync(privateKeyPath, "utf8");
            const expires = readCertificateExpiry(cert);
            const valid = isCertificateValid(cert, renewDaysBeforeExpiry);

            if (valid) {
                return { valid: true, domain, cert, key, expires };
            }
        } catch (e) {
            console.error(`[@cocreate/certificates] Error reading certificate for ${domain}:`, e.message);
        }
    }

    const hasValidCert = await check(domain, organization_id);
    if (hasValidCert && fs.existsSync(fullchainPath) && fs.existsSync(privateKeyPath)) {
        try {
            const cert = fs.readFileSync(fullchainPath, "utf8");
            const key = fs.readFileSync(privateKeyPath, "utf8");
            const expires = readCertificateExpiry(cert);
            const valid = isCertificateValid(cert, renewDaysBeforeExpiry);

            return { valid, domain, cert, key, expires };
        } catch (e) {
            console.error(`[@cocreate/certificates] Error reading certificate for ${domain}:`, e.message);
        }
    }

    return { valid: false, domain, cert: null, key: null, expires: null };
}

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
        SNICallback: sniCallback,
        sniCallback
    };
}

export default { init };