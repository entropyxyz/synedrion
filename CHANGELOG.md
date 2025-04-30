# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.3.1] - in development

### Fixed

- Removed `HasWide` requirement from `PaillierParams` types, in favor of `Extendable` and `MulWide` with blanket impl for all `Uint`s. ([#205])


[#205]: https://github.com/entropyxyz/synedrion/pull/205


## [0.3.0] - 2025-04-07

### Changed

- Switched the protocol framework to `manul`. ([#156])
- Updated the scheme to CGGMP'24. ([#170])
- Bumped MSRV to 1.83 ([#176])
- The API is now generic over the elliptic curve ([#186])
- Added `k256` (Secp256k1 parameters), `bip32` (BIP32 support), and `dev` (`tiny-curve` parameters) features. ([#199])
- Added a `Digest` type to `SchemeParams`. ([#204])


[#156]: https://github.com/entropyxyz/synedrion/pull/156
[#170]: https://github.com/entropyxyz/synedrion/pull/170
[#176]: https://github.com/entropyxyz/synedrion/pull/176
[#186]: https://github.com/entropyxyz/synedrion/pull/186
[#199]: https://github.com/entropyxyz/synedrion/pull/199
[#204]: https://github.com/entropyxyz/synedrion/pull/204


## [0.2.0] - 2024-11-17

- Signature and elliptic curve dependencies reset back to stable versions. ([#154])


[#154]: https://github.com/entropyxyz/synedrion/pull/154


## [0.2.0-pre.0] - 2024-10-03

### Changed

- `FirstRound::Context` renamed to `Inputs`. ([#102])
- `Payload` and `Artifact` values are hidden in wrapper types where they were previously exposed. ([#102])
- A number of crates set to their `pre` releases hinging on the `pre` release of `crypto-bigint`. ([#120])


### Added

- A basic implementation of threshold key resharing protocol. ([#96])


[#96]: https://github.com/entropyxyz/synedrion/pull/96
[#102]: https://github.com/entropyxyz/synedrion/pull/102
[#120]: https://github.com/entropyxyz/synedrion/pull/120


## [0.1.0] - 2023-12-07

Initial release.


[0.1.0]: https://github.com/entropyxyz/synedrion/releases/tag/release/v0.1.0
[0.2.0-pre.0]: https://github.com/entropyxyz/synedrion/releases/tag/release/v0.2.0-pre.0
[0.2.0]: https://github.com/entropyxyz/synedrion/releases/tag/release/v0.2.0
[0.3.0]: https://github.com/entropyxyz/synedrion/releases/tag/release/v0.3.0
