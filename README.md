# Synedrion


[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![License][license-image]
[![Coverage][coverage-image]][coverage-link]

[crate-image]: https://img.shields.io/crates/v/synedrion.svg
[crate-link]: https://crates.io/crates/synedrion
[docs-image]: https://docs.rs/synedrion/badge.svg
[docs-link]: https://docs.rs/synedrion/
[license-image]: https://img.shields.io/crates/l/synedrion
[coverage-image]: https://codecov.io/gh/entropyxyz/synedrion/branch/master/graph/badge.svg
[coverage-link]: https://codecov.io/gh/entropyxyz/synedrion

### A threshold signing library based on the CGGMP'21 scheme.

**WARNING:** the library is a work in progress (see [Issues](https://github.com/entropyxyz/synedrion/issues)), and has not been audited. Use at your own risk.


This library is an implementation of a scheme described in "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts" by R. Canetti, R. Gennaro, S. Goldfeder, N. Makriyannis, and U. Peled (preprint is available at <https://eprint.iacr.org/2021/060>, and the published version at <https://dl.acm.org/doi/10.1145/3372297.3423367>).


## Protocols

The library implements the following protocols from the paper:

- ECDSA Key-Generation - generates the initial secret key shares and distributes the public counterparts between the nodes;
- Auxiliary Info. & Key Refresh in Three Rounds - generates updates to the secret key shares and auxiliary information required for ZK proofs;
- ECDSA Pre-Signing (Three-Round w/ `O(n^2)` Identification Cost) - performs all the signing calculations that do not depend on the message that is being signed;
- ECDSA Signing (for Three-Round Presigning) - finishes up signing given a pre-hashed message.

The following components are work in progress:

- Full support for identifiable aborts - proofs are currently being generated when malicious behavior is detected, but no API for their checking is exposed; see <https://github.com/entropyxyz/synedrion/issues/43>;
- ECDSA Pre-Signing & Signing (Six-Round w/ `O(n)` Identification Cost) - see the tracking issue <https://github.com/entropyxyz/synedrion/issues/36>;
- Threshold signing - basic functionality is available via [`ThresholdKeyShare`](https://docs.rs/synedrion/latest/synedrion/struct.ThresholdKeyShare.html), see <https://github.com/entropyxyz/synedrion/issues/20> for more details;
- Multiple shares per party - see <https://github.com/entropyxyz/synedrion/issues/31>;
- Generic support for arbitrary curves - currently SECP256k1 is hardcoded, see <https://github.com/entropyxyz/synedrion/issues/27> for more details.


## High-level API

The library exposes a state-machine-like API which is the optimal choice for the majority of users. The set of available protocols is modified to match the common tasks:
- **KeyGen** is a merge of Key-Generation and Key Refresh protocols from the paper, generating full key shares with the auxiliary information;
- **KeyRefresh** is the Key Refresh protocol by itself, used for updating the key shares; and
- **InteractiveSigning** is a merge of 3-round Presigning and the corresponding Signing protocols.

The initial state for each protocol is instantiated by calling a function from the [`sessions`](https://docs.rs/synedrion/latest/synedrion/sessions/index.html) module (e.g. [`make_key_gen_session`](https://docs.rs/synedrion/latest/synedrion/sessions/fn.make_key_gen_session.html) for the KeyGen protocol). Besides the RNG each protocol constructor takes the following common parameters:
- The randomness shared by all other participants. This is used to generate the session ID which is included in the messages and is necessary to distinguish between parallel executions of the same protocol on the same machine;
- A signer object to sign outgoing messages;
- A list of verifiers corresponding to all the nodes participating in this session (that is, it includes the verifier of the local node).

Note that the order of the verifiers corresponds to the order of parties in the [`KeyShare`](https://docs.rs/synedrion/latest/synedrion/struct.KeyShare.html) object. That is, if you are executing a KeyGen protocol, the returned `KeyShare` will have shares in the order of the given `verifiers`, and if you are executing a KeyRefresh or InteractiveSigning protocol (which take a `KeyShare` as one of the inputs), the order of the shares in the used `KeyShare` must match the order in `verifiers`.

After the initial state is created, it goes through several rounds, in each of which it is used to create outgoing messages, verify and process the incoming messages, and finalize the round, creating a new state or the result. This would typically happen in a loop:
```ignore
// <<< `session` was created by one of the constructors >>>

let mut session = session;
let mut cached_messages = Vec::new();

let key = session.verifier();

loop {
    // This is kept in the main task since it's mutable,
    // and we don't want to bother with synchronization.
    let mut accum = session.make_accumulator();

    // Note: generating/sending messages and verifying newly received messages
    // can be done in parallel, with the results being assembled into `accum`
    // sequentially in the host task.

    let destinations = session.message_destinations();
    for destination in destinations.iter() {
        // In production usage, this will happen in a spawned task
        // (since it can take some time to create a message),
        // and the artifact will be sent back to the host task
        // to be added to the accumulator.
        let (message, artifact) = session
            .make_message(&mut OsRng, destination)
            .unwrap();

        // <<< send out `message` to `destination` here >>>

        // This will happen in a host task
        accum.add_artifact(artifact).unwrap();
    }

    for preprocessed in cached_messages {
        // In production usage, this will happen in a spawned task.
        let result = session.process_message(preprocessed).unwrap();

        // This will happen in a host task.
        accum.add_processed_message(result).unwrap().unwrap();
    }

    while !session.can_finalize(&accum).unwrap() {
        // This can be checked if a timeout expired, to see which nodes have not responded yet.
        let unresponsive_parties = session.missing_messages(&accum);
        assert!(!unresponsive_parties.is_empty());

        let (from, message) = // <<< receive `message` from `from` here >>>

        // Perform quick checks before proceeding with the verification.
        let preprocessed = session
            .preprocess_message(&mut accum, &from, message)
            .unwrap();

        if let Some(preprocessed) = preprocessed {
            // In production usage, this will happen in a spawned task.
            let result = session.process_message(preprocessed).unwrap();

            // This will happen in a host task.
            accum.add_processed_message(result).unwrap().unwrap();
        }
    }

    match session.finalize_round(&mut OsRng, accum).unwrap() {
        FinalizeOutcome::Success(result) => break result,
        FinalizeOutcome::AnotherRound {
            session: new_session,
            cached_messages: new_cached_messages,
        } => {
            session = new_session;
            cached_messages = new_cached_messages;
        }
    }
}
```

The library follows a "sans-I/O" design, so the user API is a little convoluted. See below for explanations on what is happening in the loop.


### Accumulator

The `session` object is immutable so that it could be passed to spawned tasks by reference. You may want to offload creating new messages and processing incoming ones to tasks since those things may take a significant amount of time (up to seconds). The accumulator, created anew in each round, is located in the main task and holds the results of spawned tasks.


### Cached messages

It may happen that some nodes have already received all the messages from this round and started the next one, sending you messages from that round. If that happens, those messages will be saved in the accumulator, and returned on finalization as a part of `FinalizeOutcome::AnotherRound`. It is the user's responsibility to apply them in the next round.


### Possible results

The state of each protocol is parametrized by a type implementing [`ProtocolResult`](https://docs.rs/synedrion/latest/synedrion/trait.ProtocolResult.html). The `Success` type denotes the type of the contents of `FinalizeOutcome::Success` (e.g. it will be `KeyShare` or `RecoverableSignature`). The two remaining types correspond to some of the possible errors.


### Errors

Every method of the state returns [`Error`](https://docs.rs/synedrion/latest/synedrion/sessions/enum.Error.html) or one of its subcomponents (if it can be narrowed down) as a possible error. There are four different types of errors:
- [`Local`](https://docs.rs/synedrion/latest/synedrion/sessions/enum.Error.html#variant.Local) - this indicates a usage error (unfortunately, not everything can be enforced by types) or a bug in the library;
- [`Provable`](https://docs.rs/synedrion/latest/synedrion/sessions/enum.Error.html#variant.Provable) - this is the case where a remote party is at fault and can be immediately identified as such. The contents of this variant can be published are sufficient to prove that the party with the given verifying key misbehaved.
- [`Proof`](https://docs.rs/synedrion/latest/synedrion/sessions/enum.Error.html#variant.Proof) - this is a more complicated case when there has been a fault at the protocol level, but the faulty party cannot be immediately identified. The contents of this variant is a proof that you did your share of work correctly; some arbiter must collect these proofs from every party, and at least one will necessarily turn out missing or invalid, indicating the faulty party.
- [`Remote`](https://docs.rs/synedrion/latest/synedrion/sessions/enum.Error.html#variant.Remote) - indicates that there has been a problem with the remote party, but the fault cannot be proven at the library's level. For example, if the message's signature is invalid or the message is corrupted, we cannot publish that as a proof of misbehavior, because we could have easily forged such a message ourselves. Depending on the delivery channel used one may or may not have some tangible evidence against the remote node in this case, but it cannot be handled at this library's level. Alternatively, one may flag such a node internally as unreliable, which can be further used to, say, avoid selecting it for future sessions.
