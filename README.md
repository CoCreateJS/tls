Here is the accurately updated, tailored README for `@cocreate/server-tls` based directly on your provided source code implementation. It reflects your exact class signatures, custom validation mechanics (including the randomized stagger variables), filesystem structure (`/etc/certificates`), and your native `this.crud` database/file injection flows.

# @cocreate/server-tls

An automated, multi-tenant TLS (Automated Certificate Management Environment) client and automated SSL/TLS provisioning wrapper built on top of `certificates-client`. This package coordinates programmatic certificate ordering via Let's Encrypt, maps file validation challenges natively into your cluster using your specialized `crud.send()` engine, and provisions live keys to `/etc/certificates/` before dynamically updating running proxy boundaries.

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [How it Works](#how-it-works)
* [API Reference](#api-reference)
* [How to Contribute](#how-to-contribute)
* [License](#license)

---

## Features

* **Automated Account & Key Creation:** Gracefully initializes `/etc/certificates`, provisions or loads an asymmetric `account.pem` key profile, and dynamically registers newly generated account contexts with the TLS Directory.
* **Reactive Multi-Node Challenge Handling:** Writes `http-01` challenge validation payloads natively directly into persistent network collection tracks (`array: "files"`), enabling external verification processes to easily query and clear challenges on any active cluster node.
* **Staggered Expiration Guards:** Leverages unique math-random constants (`DAYS`, `HOURS`, `MINUTES`) across server instances to prevent simultaneous, blocking stampedes when scanning and renewing multi-tenant custom domains.
* **Inline Local Filesystem Provisioning:** Auto-writes validated credentials (`fullchain.pem` and `private-key.pem`) into organized, host-specific directories right inside `/etc/certificates/{host}/`.
* **Hot Proxy Re-Initialization:** Calls hot proxy callbacks (`this.proxy.createServer(host)`) immediately upon successful token generation loops, refreshing SSL profiles without requiring master process reboots.

---

## Installation

```bash
npm install @cocreate/server-tls

```

---

## Usage

### Class Initialization

Inject your cluster's routing `proxy` interface and core database `crud` middleware service layer right into the instance constructor context:

```javascript
const CoCreateCertificates = require('@cocreate/server-tls');

const proxyInstance = {
  createServer: (host) => console.log(`Hot-reloaded server certificates for: ${host}`)
};

const crudInstance = {
  send: async (payload) => { /* ... handling database syncing ... */ },
  getOrganization: async ({ host, organization_id }) => { /* ... fetches organization document ... */ }
};

// Initializes paths, sets up permissions, loads/creates account.pem, and sets up Let's Encrypt connection
const CertificatesManager = new CoCreateCertificates(proxyInstance, crudInstance);

```

### Checking and Provisioning TLS Dynamically

Intercept traffic requests or cron loops natively, evaluating if a domain possesses valid, active SSL coverage or requires a zero-friction automated provisioning lifecycle:

```javascript
const targetHost = "my-custom-domain.app.cocreate.js";
const orgId = "652c8d62679eca03e0b116a7";

// Bypasses localhost/127.0.0.1, scans local caches, validates file states, or auto-provisions a new bundle
const operational = await CertificatesManager.checkCertificate(targetHost, orgId);

if (operational) {
  console.log(`Secure gateway communication channels verified for ${targetHost}`);
} else {
  console.log(`Failed to configure or provision certificates for ${targetHost}`);
}

```

---

## How it Works

1. **Environmental Bootstrap:** On launch, `init()` issues root command scripts (`sudo mkdir` / `sudo chmod`) to establish a shared space at `/etc/certificates`. It scans for `account.pem`; if missing, it spawns a fresh private key profile via `forge.createPrivateKey()` and calls Let's Encrypt (`client.createAccount`) to sign the structural Terms of Service agreements.
2. **Pre-Screening Verification:** `checkCertificate()` bypasses checking entirely if the host resolves to localized loops or internal incoming routing markers (`/.well-known/certificates-challenge/`). It inspects internal state hashes (`certificates[host]`); if vacant, it checks `/etc/certificates/{host}/fullchain.pem` directly from disks.
3. **Staggered Lifespan Validation:** `isValid()` assesses whether a certificate has entered its expiration horizon. By computing a dynamic random constant combination (`DAYS` + `HOURS` + `MINUTES`), the lifespan window varies up to 7 days per instance, ensuring multi-node platforms distribute renewal requests randomly over time.
4. **Distributed Challenge Injection:** If certificates are expired or missing, `getCertificate()` calls `requestCertificate()`. When the `client.auto()` handshake processes tokens, `challengeCreateFn` hooks fire. It pipes a structure using `this.crud.send()` with a method payload targeting `object.create`, pushing the plaintext validation key into your data engines where public requests can catch it.
5. **Disk Commit & Hot Swap:** Once the Let's Encrypt engine validates your token, `challengeRemoveFn` clears verification metrics through `object.delete`. The returned payload extracts the public chains, writes `fullchain.pem` and `private-key.pem` files to disk, pushes state blocks to the `organizations` collection array, and triggers `this.proxy.createServer(host)` to complete the loop.

---

## API Reference

### Core Class Instance Methods

| Method | Arguments | Returns | Description |
| --- | --- | --- | --- |
| **`init()`** | *None* | `Promise<void>` | **Internal.** Sets up local directory layout, loads/stores account keys, and boots the TLS interface. |
| **`checkCertificate(host, orgId, pathname)`** | `host: String`, `orgId: String`, `pathname: String` | `Promise<Boolean>` | High-level execution entry point. Bypasses dev routes, checks caches/disks, and manages provisioning rollouts. |
| **`getCertificate(host, orgId)`** | `host: String`, `orgId: String` | `Promise<Boolean>` | Loads tenant details via `this.crud.getOrganization()`. Reuses valid db keys or invokes a new order lifecycle. |
| **`requestCertificate(host, pos, hostObj, orgId, wildcard)`** | `String, Number, Object, String, Boolean` | `Promise<Boolean>` | Prepares CSR blocks, handles challenge loops, syncs structures with the database, and saves file buffers. |
| **`isValid(expires)`** | `expires: Date` | `Boolean|undefined` | Compares signature expiration maps against calculated time horizons to decide if a domain requires active renewal. |
| **`setCertificate(host, exp, orgId, path, cert, key)`** | `String, Date, String, String, String, String` | `void` | Writes certificate credentials to disk, registers metrics inside internal lists, and tells proxies to bind the port. |

---

## How to Contribute

We encourage contribution to our libraries (you might even score some nifty swag), please see our [CONTRIBUTING.md](https://github.com/CoCreateJS/CoCreate-server-tls/blob/master/CONTRIBUTING.md) guide for details. If you encounter any bugs or wish to make feature requests, please submit an issue on our [GitHub Issues](https://github.com/CoCreateJS/CoCreate-server-tls/issues) tracker. We want this library to be community-driven, and CoCreate led. We need your help to realize this goal.

For broader system configurations and API guides, please visit our [CoCreate TLS Documentation](https://cocreatejs.com/docs/server-tls).

---

## License

This software is dual-licensed under the GNU Affero General Public License version 3 (AGPLv3) and a commercial license.

* **Open Source Use:** For open-source projects and non-commercial use, this software is available under the AGPLv3. For the full license text, see the LICENSE file.
* **Commercial Use:** For-profit companies and individuals intending to use this software for commercial purposes must obtain a commercial license. The commercial license is available when you sign up for an API key on our website.