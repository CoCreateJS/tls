# [1.6.0](https://github.com/CoCreateJS/tls/compare/v1.5.1...v1.6.0) (2026-11-02)


### Bug Fixes

* add Deno specific entries to .gitignore ([f77a858](https://github.com/CoCreateJS/tls/commit/f77a85841ee9fbfbbc503bc765742454cef5e412))
* bump versions ([c5b256d](https://github.com/CoCreateJS/tls/commit/c5b256dd17982f3a12ab6ab80cef84a7e6c26101))
* correct keyPath to include a leading dot for certificates directory ([8ccb6f1](https://github.com/CoCreateJS/tls/commit/8ccb6f1063dfd61240ecd12f34c2591123a49ee8))
* regenerate invalid local TLS certificates ([72de9da](https://github.com/CoCreateJS/tls/commit/72de9dabbed730bd2ecb7c2f5d2c2c89950fd594))
* remove exports field from package.json ([5c8c6ae](https://github.com/CoCreateJS/tls/commit/5c8c6ae6769d20c497e01362f9e3d3039f6593ff))
* remove trailing slash from node_modules entry in .gitignore ([a6fdc97](https://github.com/CoCreateJS/tls/commit/a6fdc973fdc481b62ff2e35c7a65bf8d96731de1))
* update GitHub Actions to use latest versions and sync package.json description ([ed05aff](https://github.com/CoCreateJS/tls/commit/ed05aff305d2e884c1dcc96be03d88dfb7a0b9b4))
* update organization_id handling for dynamic resolution in ACME requests ([27738bb](https://github.com/CoCreateJS/tls/commit/27738bb6b42ce9d400e3be29fb268dc22172f56b))


### Features

* add @cocreate/config as a dependency and refactor certificate management logic ([28f251b](https://github.com/CoCreateJS/tls/commit/28f251b9e8006ed85a4d20d00bca3d80a629b08d))
* add @cocreate/utils as a dependency and refactor CSR generation to use security utilities ([18e853d](https://github.com/CoCreateJS/tls/commit/18e853d57257405564074a871b8a797f79e3fda7))
* add webpack configuration and self-cleaning bundle plugin ([ced8fe2](https://github.com/CoCreateJS/tls/commit/ced8fe2f97a6962f9f3e4120d6e4d56df49334e7))
* bumped all dependency versions ([0d536c6](https://github.com/CoCreateJS/tls/commit/0d536c65a21463a50527cfae52c7f42602a79f94))
* overhaul ACME client implementation and remove webpack configuration ([de9b685](https://github.com/CoCreateJS/tls/commit/de9b685ba2acff13602f8887726bb9d17e52b52e))
* refactor certificate management with async file operations and enhanced error handling ([028d1fc](https://github.com/CoCreateJS/tls/commit/028d1fcc69a94e649fa559f308e6ead52cfc14bf))
* remove manual workflow configuration ([ae0e6a8](https://github.com/CoCreateJS/tls/commit/ae0e6a8ec75332779d985b30d74b9403daa84ceb))
* rename ACME to Certificates and update related references ([92422df](https://github.com/CoCreateJS/tls/commit/92422df33e9f516b9ae08a493c017011c1f19238))
* update Let's Encrypt directory URLs to the latest API endpoints ([dcb1959](https://github.com/CoCreateJS/tls/commit/dcb1959bb3355ffb55195d4347f8359d471494d9))

## [1.5.1](https://github.com/CoCreateJS/tls/compare/v1.5.0...v1.5.1) (2026-07-19)


### Bug Fixes

* set default branch to main ([383f061](https://github.com/CoCreateJS/tls/commit/383f061a286d5f0016c33c28acca72c79af3edf9))

# [1.5.0](https://github.com/CoCreateJS/tls/compare/v1.4.1...v1.5.0) (2026-07-19)


### Features

* enhance DNS verification and secure file handling in TLS client ([0c92815](https://github.com/CoCreateJS/tls/commit/0c92815879b5a390b1b4697a8d530294bb78b1dd))

## [1.4.1](https://github.com/CoCreateJS/tls/compare/v1.4.0...v1.4.1) (2026-07-17)


### Bug Fixes

* bump dependencies ([a6c9134](https://github.com/CoCreateJS/tls/commit/a6c9134248057e7c99472f7c59f1a6b5db961784))
* update certificates-client dependency version to ^5.4.0 ([31be66c](https://github.com/CoCreateJS/tls/commit/31be66c2cfecb9fb82efd8e99d0e076fc4a178d5))

# [1.4.0](https://github.com/CoCreateJS/tls/compare/v1.3.3...v1.4.0) (2026-07-17)


### Bug Fixes

* improve error handling and remove redundant server reference assignments in init function ([69831fe](https://github.com/CoCreateJS/tls/commit/69831fee351f103e60579b34bb915fbed655b3a1))


### Features

* update automated workflow and release configuration for improved semantic release handling ([90145c1](https://github.com/CoCreateJS/tls/commit/90145c12f6421d03cbb66d8f4b7c29891b1d2ef0))

## [1.3.3](https://github.com/CoCreateJS/tls/compare/v1.3.2...v1.3.3) (2026-07-14)


### Bug Fixes

* removed post install ([cc2012f](https://github.com/CoCreateJS/tls/commit/cc2012f8ada625665074ecbaad14b895358a3ae7))
* semantic version handling. Reorganize .gitignore for improved clarity and structure ([6e69e47](https://github.com/CoCreateJS/tls/commit/6e69e47e1643255a623bee33279320d0a825ce4f))
* update module export to ES6 syntax in release.config.js ([5833855](https://github.com/CoCreateJS/tls/commit/58338552088e727bb7abbeb77107dcb87f82bfa5))
* update package.json to use ESM and restructure server/client entry points ([6eb6796](https://github.com/CoCreateJS/tls/commit/6eb679673260922698716bf5e5e35a5044a1dbd1))

## [1.3.2](https://github.com/CoCreateJS/tls/compare/v1.3.1...v1.3.2) (2025-09-06)


### Bug Fixes

* await async function calls ([cf151f1](https://github.com/CoCreateJS/tls/commit/cf151f186b4893411f273a6a3e3f08b87093b72c))
* formating ([bcce249](https://github.com/CoCreateJS/tls/commit/bcce24906478e43aa4b1845c9f9099623551128e))

## [1.3.1](https://github.com/CoCreateJS/tls/compare/v1.3.0...v1.3.1) (2025-05-01)


### Bug Fixes

* update [@cocreate](https://github.com/cocreate) dependencies ([f2f3db6](https://github.com/CoCreateJS/tls/commit/f2f3db6cf8ecf15e91edc64ab463d6bc34c193f5))
* webpack.config and devdependencies ([41a8a22](https://github.com/CoCreateJS/tls/commit/41a8a22223eff38cc7c439c05a11e8d31ae9b8f9))

# [1.3.0](https://github.com/CoCreateJS/tls/compare/v1.2.14...v1.3.0) (2024-11-04)


### Bug Fixes

* prettier.config options ([9a92da8](https://github.com/CoCreateJS/tls/commit/9a92da8fd7fc6443ee79b8b6241847d490397cb4))


### Features

* add prettier.config.js and format files ([32b0946](https://github.com/CoCreateJS/tls/commit/32b0946c44885447be6c34eaf8ad7e7d576e139f))

## [1.2.14](https://github.com/CoCreateJS/tls/compare/v1.2.13...v1.2.14) (2024-07-23)


### Bug Fixes

* convert key to string before saving ([a8b80c7](https://github.com/CoCreateJS/tls/commit/a8b80c7c5f37d2ed2b401509b1889faad6f79407))

## [1.2.13](https://github.com/CoCreateJS/tls/compare/v1.2.12...v1.2.13) (2024-06-23)


### Bug Fixes

* bump dependencies ([a10999f](https://github.com/CoCreateJS/tls/commit/a10999f40dd93bc007f4658e6b278b40c905f440))

## [1.2.12](https://github.com/CoCreateJS/tls/compare/v1.2.11...v1.2.12) (2024-06-23)


### Bug Fixes

* update dependencies ([15a5ca1](https://github.com/CoCreateJS/tls/commit/15a5ca13c7e22e8cbccb5cc937aacb4d98b9dddf))

## [1.2.11](https://github.com/CoCreateJS/tls/compare/v1.2.10...v1.2.11) (2024-06-23)


### Bug Fixes

* demo css ([1f4a35c](https://github.com/CoCreateJS/tls/commit/1f4a35cdf2e101803c8eafc3fefa149ad2719016))

## [1.2.10](https://github.com/CoCreateJS/tls/compare/v1.2.9...v1.2.10) (2024-04-26)


### Bug Fixes

* merge hostObject to retain previous configuration reltaed to database ([c9d7c16](https://github.com/CoCreateJS/tls/commit/c9d7c160dfd07f3f5a91c9e2cebab5da2d86ec1c))

## [1.2.9](https://github.com/CoCreateJS/tls/compare/v1.2.8...v1.2.9) (2024-04-10)


### Bug Fixes

* handling organization_id  if undefined ([c537cd1](https://github.com/CoCreateJS/tls/commit/c537cd18ef84d4b6d102e2028321a623756c0dfc))

## [1.2.8](https://github.com/CoCreateJS/tls/compare/v1.2.7...v1.2.8) (2024-03-18)


### Bug Fixes

* removed uppercase ([c273578](https://github.com/CoCreateJS/tls/commit/c2735787b95f6c50e5f06fb133a5d6cac2d0d00d))

## [1.2.7](https://github.com/CoCreateJS/tls/compare/v1.2.6...v1.2.7) (2024-03-18)


### Bug Fixes

* removed replaced keyword spaces with hyphens ([7e041d6](https://github.com/CoCreateJS/tls/commit/7e041d669135dd8c372864a32d9a17bcf33feace))

## [1.2.6](https://github.com/CoCreateJS/tls/compare/v1.2.5...v1.2.6) (2024-03-18)


### Bug Fixes

* descriptions ([9077e05](https://github.com/CoCreateJS/tls/commit/9077e05c7de4cef797c6287bd7056f2b3abf6093))

## [1.2.5](https://github.com/CoCreateJS/tls/compare/v1.2.4...v1.2.5) (2024-02-05)


### Bug Fixes

* Removed https://cdn.CoCreateJS.com/latest/CoCreate.min.css ([f203e98](https://github.com/CoCreateJS/tls/commit/f203e985e9652fc1a494aa3c2bec0763f50b4077))

## [1.2.4](https://github.com/CoCreateJS/tls/compare/v1.2.3...v1.2.4) (2024-01-30)


### Bug Fixes

* removed getHost ([3d58b30](https://github.com/CoCreateJS/tls/commit/3d58b3046f2444b76c9ce6a3f5dd78c6a17d3ca6))

## [1.2.3](https://github.com/CoCreateJS/tls/compare/v1.2.2...v1.2.3) (2024-01-08)


### Bug Fixes

* update to logging ([8e3946d](https://github.com/CoCreateJS/tls/commit/8e3946d6dc8af2719c9d76484e2f35d5b3dbee7b))

## [1.2.2](https://github.com/CoCreateJS/tls/compare/v1.2.1...v1.2.2) (2024-01-08)


### Bug Fixes

* ssl syncing ([65b226a](https://github.com/CoCreateJS/tls/commit/65b226a16487f3b8b6862092f6b3e83d8f119f51))

## [1.2.1](https://github.com/CoCreateJS/tls/compare/v1.2.0...v1.2.1) (2024-01-08)


### Bug Fixes

* handling hostPosition ([fa105b1](https://github.com/CoCreateJS/tls/commit/fa105b1a35927380cd88549d7675eebd2d80a163))

# [1.2.0](https://github.com/CoCreateJS/tls/compare/v1.1.3...v1.2.0) (2024-01-08)


### Bug Fixes

* applied host to define environment/branch ([6931a9b](https://github.com/CoCreateJS/tls/commit/6931a9b81bfdf5b095534f7f42c6b9df1ea99141))
* handle ssl from host array ([fd45091](https://github.com/CoCreateJS/tls/commit/fd450914804b389647af52a1c40f6569e44066cf))
* setCertificate handle writeFileSync and hostPosition defined to save to host object ([29e794d](https://github.com/CoCreateJS/tls/commit/29e794de6d38584462ea926f3ef957d42b97c0bf))


### Features

* bumped CoCreate dependencies to their latest versions ([c25e34d](https://github.com/CoCreateJS/tls/commit/c25e34de1e47f660c773c7ea242e4ff2b060c936))
* host contains sert and key ([11380ac](https://github.com/CoCreateJS/tls/commit/11380acb7463e13d14a3e6ea856c288cef1d26c4))
* use crud.getHost and crud.getorganization ([574718b](https://github.com/CoCreateJS/tls/commit/574718b0ae035b63f6e70f4423ea1fd484bc80cc))

## [1.1.3](https://github.com/CoCreateJS/tls/compare/v1.1.2...v1.1.3) (2024-01-03)


### Bug Fixes

* added licencing details ([220ee61](https://github.com/CoCreateJS/tls/commit/220ee61a9d954a62a5c505a34995e287f6f01c12))
* get organization_id and update certificate paths ([6ae3c71](https://github.com/CoCreateJS/tls/commit/6ae3c71cc1f16d6f93ec767bd5b4dae28b669764))

## [1.1.2](https://github.com/CoCreateJS/tls/compare/v1.1.1...v1.1.2) (2024-01-01)


### Bug Fixes

* added proxy.createServer ([ec8e37f](https://github.com/CoCreateJS/tls/commit/ec8e37fbce371bd615807f290e695e2880572fb8))

## [1.1.1](https://github.com/CoCreateJS/tls/compare/v1.1.0...v1.1.1) (2024-01-01)


### Bug Fixes

* check pathname for certificates-challenge and return true ([0b90df5](https://github.com/CoCreateJS/tls/commit/0b90df504cb452bc60a822ea55c0987c71e3fa11))

# [1.1.0](https://github.com/CoCreateJS/tls/compare/v1.0.0...v1.1.0) (2023-12-31)


### Bug Fixes

* filenames ([23735c4](https://github.com/CoCreateJS/tls/commit/23735c44f30cdd848959a3046ac40665302f38b6))
* Wraped in class to use with modules ([4ff5bea](https://github.com/CoCreateJS/tls/commit/4ff5beabf9aee2b53d41839d3c6f276344726cb3))


### Features

* emit certificateCreated ([eb5cdc6](https://github.com/CoCreateJS/tls/commit/eb5cdc6142c7bfd15f548bbdaf908c33e3f6c19f))
* store certificates using crud so other nodes can reused ([aea5f15](https://github.com/CoCreateJS/tls/commit/aea5f1557f358934f6b08c9f94a734af80a56f6e))

# 1.0.0 (2023-12-30)


### Features

* Intial Release ([245a6ca](https://github.com/CoCreateJS/tls/commit/245a6ca55bcdc0d8285f6d0db0b35574991d29c4))
