# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.3.0] - in development

- Switch the protocol framework to `manul`. ([#156])
- Bumped MSRV to 1.83 ([#176])

[#156]: https://github.com/entropyxyz/synedrion/pull/156


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
