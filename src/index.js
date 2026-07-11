/********************************************************************************
 * Copyright (C) 2023 CoCreate and Contributors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 ********************************************************************************/

// Commercial Licensing Information:
// For commercial use of this software without the copyleft provisions of the AGPLv3,
// you must obtain a commercial license from CoCreate LLC.
// For details, visit <https://cocreate.app/licenses/> or contact us at sales@cocreate.app.

import { Client, forge } from "acme-client";
import fs from "fs";
import https from "https";
import tls from "tls";
import { promisify } from "node:util";
import { exec as childExec } from "node:child_process";

const exec = promisify(childExec);

// ==========================================
// Module-Level Sandbox State (ESM Singleton Container)
// ==========================================
let server = null; // Direct reference used across all module functions
const certificates = {};
const email = "ssl@cocreate.app";
const keyPath = "/etc/certificates/";
let client;
const hosts = {};

const DAYS = Math.floor(Math.random() * 7);
const HOURS = Math.floor(Math.random() * 24);
const MINUTES = Math.floor(Math.random() * 60);

/**
 * Bootstraps the ACME account keys, directories, and instantiates the
 * secure HTTPS server context, attaching it back to the parent server reference.
 * @param {Object} parentServer - Parent CoCreateServer singleton instance
 */
export async function init(parentServer) {
    try {
        server = parentServer;

        // Apply references directly to the server object to fulfill the interface contract
        if (server) {
            server.certificate = {
                init,
                load,
                sniCallback,
                request,
                get,
                check,
                isValid,
                set
            };
        }

        await exec("sudo mkdir -p /etc/certificates");
        await exec("sudo chmod 777 /etc/certificates");

        const accountKeyPath = `${keyPath}account.pem`;
        let accountKey = "";
        let isNewAccount = false;

        if (!fs.existsSync(accountKeyPath)) {
            accountKey = await forge.createPrivateKey();
            isNewAccount = true;
            fs.writeFileSync(accountKeyPath, accountKey);
        } else {
            accountKey = fs.readFileSync(accountKeyPath, "utf8");
        }

        client = new Client({
            directoryUrl: "https://acme-v02.api.letsencrypt.org/directory",
            accountKey: accountKey
        });

        if (isNewAccount) {
            try {
                await client.createAccount({
                    termsOfServiceAgreed: true,
                    contact: [`mailto:${email}`]
                });
                console.log("[@cocreate/acme] ACME authority account created successfully!");
            } catch (error) {
                try {
                    fs.unlinkSync(accountKeyPath);
                } catch (_) {}
                console.error("[@cocreate/acme] Error creating account credentials:", error.message);
            }
        }

        // Dynamically instantiate the HTTPS server with the SNI Callback context 
        // and bind it directly onto the core server object.
        if (server) {
            server.https = https.createServer({
                SNICallback: sniCallback
            });
        }
    } catch (err) {
        console.error("[@cocreate/acme] Error initializing certificate client:", err);
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
        console.error(`[@cocreate/acme] Error loading SSL certificates for domain: ${domain}`, error);
        throw error;
    }
}

/**
 * Core SNI Handshake implementation. Resolves domains dynamically and loads TLS Context.
 * @param {string} domain - Incoming target SNI hostname
 * @param {Function} cb - Resolution completion callback
 */
export async function sniCallback(domain, cb) {
    try {
        // Verify domain authorization
        const isValidDomain = await check(domain);
        
        if (isValidDomain) {
            const credentials = load(domain);
            const sslContext = tls.createSecureContext(credentials);
            cb(null, sslContext);
        } else {
            cb(new Error(`[@cocreate/acme] Unauthorized secure request for domain: ${domain}`));
        }
    } catch (error) {
        console.error(`[@cocreate/acme] Error in SNI callback for domain: ${domain}`, error);
        cb(error);
    }
}

/**
 * Requests certificate generation dynamically via ACME protocols.
 */
export async function request(host, hostPosition, hostObject, organization_id, wildcard = false) {
    try {
        const hostKeyPath = `${keyPath}${host}/`;
        
        if (!fs.existsSync(hostKeyPath)) {
            fs.mkdirSync(hostKeyPath, { recursive: true });
        }

        const domains = wildcard ? [host, `*.${host}`] : [host];
        let [key, csr] = await forge.createCsr({ commonName: domains[0], altNames: domains });
        let challenge_id = "";

        const cert = await client.auto({
            csr,
            email: [email],
            termsOfServiceAgreed: true,
            challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                if (challenge.type === "http-01" && server && server.crud) {
                    const httpChallenge = await server.crud.send({
                        method: "object.create",
                        host,
                        array: "files",
                        object: {
                            "content-type": "text/plain",
                            directory: "acme-challenge",
                            host: [authz.identifier.value],
                            name: challenge.token,
                            organization_id: "652c8d62679eca03e0b116a7",
                            path: "/.well-known/acme-challenge/",
                            pathname: `/.well-known/acme-challenge/${challenge.token}`,
                            public: "true",
                            src: keyAuthorization
                        },
                        organization_id
                    });
                    if (httpChallenge?.object?.[0]) challenge_id = httpChallenge.object[0]._id;
                }
            },
            challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
                if (challenge.type === "http-01" && server && server.crud) {
                    server.crud.send({
                        method: "object.delete",
                        host,
                        array: "files",
                        object: { _id: challenge_id },
                        organization_id
                    });
                }
            }
        });

        let expires = await forge.readCertificateInfo(cert);
        expires = expires.notAfter;
        
        set(host, expires, organization_id, hostKeyPath, cert, key);
        key = key.toString("utf8");

        if (server && server.crud) {
            server.crud.send({
                method: "object.update",
                host,
                array: "organizations",
                object: {
                    _id: organization_id,
                    [`host[${hostPosition}]`]: { ...hostObject, name: host, cert, key, expires }
                },
                organization_id
            });
        }

        return true;
    } catch (error) {
        console.error(`[@cocreate/acme] Certificate failed to create for ${host}!`, error);
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

    let organization = await server.crud.getOrganization({ host, organization_id });
    if (organization.error) return false;
    if (!organization_id) organization_id = organization._id;

    if (organization.host) {
        for (let i = 0; i < organization.host.length; i++) {
            if (organization.host[i].name === host) {
                hostPosition = i;
                hostObject = organization.host[i];
                
                if (organization.host[i].cert && organization.host[i].key) {
                    let expires = await forge.readCertificateInfo(organization.host[i].cert);
                    expires = expires.notAfter;
                    
                    if (isValid(expires)) {
                        set(host, expires, organization_id, hostKeyPath, organization.host[i].cert, organization.host[i].key);
                        return true;
                    }
                }
                break;
            }
        }
        if (!hostPosition && hostPosition !== 0) return false;
    }

    return await request(host, hostPosition, hostObject, organization_id, false);
}

/**
 * Checks database registries or local systems to verify if a valid cert exists.
 */
export async function check(host, organization_id, pathname = "") {
    let hostname = host.split(":")[0];
    if (hostname === "localhost" || hostname === "127.0.0.1" || pathname.startsWith("/.well-known/acme-challenge/")) {
        return true;
    }
    if (certificates[host]) return true;

    const hostKeyPath = `${keyPath}${host}/`;
    if (fs.existsSync(`${hostKeyPath}fullchain.pem`)) {
        let cert = fs.readFileSync(`${hostKeyPath}fullchain.pem`, "utf8");
        let expires = await forge.readCertificateInfo(cert);
        expires = expires.notAfter;
        
        if (isValid(expires)) {
            set(host, expires, organization_id);
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
    let currentDate = new Date();
    currentDate.setDate(currentDate.getDate() + DAYS);
    currentDate.setHours(currentDate.getHours() + HOURS);
    currentDate.setMinutes(currentDate.getMinutes() + MINUTES);

    return (expires && currentDate < expires);
}

/**
 * Writes dynamic credentials to disk and triggers an update on the host ingress config.
 */
export function set(host, expires, organization_id, hostKeyPath, cert, key) {
    if (hostKeyPath) {
        if (!fs.existsSync(hostKeyPath)) fs.mkdirSync(hostKeyPath, { recursive: true });
        fs.writeFileSync(`${hostKeyPath}fullchain.pem`, cert);
        fs.writeFileSync(`${hostKeyPath}private-key.pem`, key);
    }

    if (server && server.ingress) {
        server.ingress.createServer(host);
    }
    certificates[host] = { expires, organization_id };
}

// Default export mimics the functional API entry point
export default {
    init,
    load,
    sniCallback,
    request,
    get,
    check,
    isValid,
    set
};