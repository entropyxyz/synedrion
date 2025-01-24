# Synedrion

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![License][license-image]
[![Build Status][build-image]][build-link]
[![Coverage][coverage-image]][coverage-link]

[crate-image]: https://img.shields.io/crates/v/synedrion.svg
[crate-link]: https://crates.io/crates/synedrion
[docs-image]: https://docs.rs/synedrion/badge.svg
[docs-link]: https://docs.rs/synedrion/
[license-image]: https://img.shields.io/crates/l/synedrion
[build-image]: https://github.com/entropyxyz/synedrion/actions/workflows/ci.yml/badge.svg?branch=master&event=push
[build-link]: https://github.com/entropyxyz/synedrion/actions?query=workflow%3Aci
[coverage-image]: https://codecov.io/gh/entropyxyz/synedrion/branch/master/graph/badge.svg
[coverage-link]: https://codecov.io/gh/entropyxyz/synedrion


### A threshold signing library based on the CGGMP'24 scheme.

**WARNING:** the library is a work in progress (see [Issues](https://github.com/entropyxyz/synedrion/issues)), and has not been audited. Use at your own risk.


This library is an implementation of a scheme described in "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts" by R. Canetti, R. Gennaro, S. Goldfeder, N. Makriyannis, and U. Peled.
Specifically, we are using the scheme as specified in the preprint at <https://eprint.iacr.org/2021/060>, revision 2024-10-21.


## Protocols

The library implements the following protocols from the paper:

- ECDSA Key-Generation - generates the initial secret key shares and distributes the public counterparts between the nodes;
- Auxiliary Info. & Key Refresh - generates updates to the secret key shares and auxiliary information required for ZK proofs;
- Auxiliary Info - the protocol above without the key refresh, only generating the auxiliary info;
- ECDSA Presigning - performs all the signing calculations that do not depend on the message that is being signed;
- ECDSA Signing - finalizes signing given a pre-hashed message.
- ECDSA Interactive Signing - the two protocols above chained one after the other acting as a single protocol. Note that currently Presigning and Signing are not available separately to ensure we can generate provable evidence on Signing faults (which requires transcript from Presigning).
- Threshold Key Resharing - technically not a part of the CGGMP'24 proper, but needed to enable threshold functionality.

All the protocols support identifiable aborts where specified by the paper, and where possible, a self-contained malicious behavior evidence will be returned, so that it can be published.

The following components are work in progress:

- Multiple shares per party - see <https://github.com/entropyxyz/synedrion/issues/31>;
- Generic support for arbitrary curves - currently SECP256k1 is hardcoded, see <https://github.com/entropyxyz/synedrion/issues/27> for more details.


## High-level API

The library uses [`manul`](https://docs.rs/manul) as a framework for running the protocols.
All the protocols expose a type implementing [`EntryPoint`](https://docs.rs/manul/latest/manul/protocol/trait.EntryPoint.html) and can be executed via [`Session`](https://docs.rs/manul/latest/manul/session/struct.Session.html).

See `manul` docs for general information on how to execute protocols in production or development environment, and how to handle errors.
