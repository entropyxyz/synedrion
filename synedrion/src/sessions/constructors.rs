use alloc::format;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};

use super::states::Session;
use crate::cggmp21::{
    auxiliary, interactive_signing, keygen_and_aux, InitError, KeyShare, KeyShareChange, PartyIdx,
    SchemeParams,
};
use crate::curve::{RecoverableSignature, Scalar};

/// Prehashed message to sign.
pub type PrehashedMessage = [u8; 32];

/// Creates the initial state for the joined KeyGen and KeyRefresh+Auxiliary protocols.
pub fn make_keygen_and_aux_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
    party_idx: PartyIdx,
) -> Result<Session<KeyShare<P>, Sig, Signer, Verifier>, InitError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig>,
    Verifier: PrehashVerifier<Sig> + Clone,
{
    Session::new::<keygen_and_aux::Round1<P>>(
        rng,
        shared_randomness,
        signer,
        party_idx,
        verifiers,
        (),
    )
}

/// Creates the initial state for the KeyRefresh+Auxiliary protocol.
pub fn make_key_refresh_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
    party_idx: PartyIdx,
) -> Result<Session<KeyShareChange<P>, Sig, Signer, Verifier>, InitError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig>,
    Verifier: PrehashVerifier<Sig> + Clone,
{
    Session::new::<auxiliary::Round1<P>>(rng, shared_randomness, signer, party_idx, verifiers, ())
}

/// Creates the initial state for the joined Presigning and Signing protocols.
pub fn make_interactive_signing_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
    key_share: &KeyShare<P>,
    prehashed_message: &PrehashedMessage,
) -> Result<Session<RecoverableSignature, Sig, Signer, Verifier>, InitError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig>,
    Verifier: PrehashVerifier<Sig> + Clone,
{
    if verifiers.len() != key_share.num_parties() {
        return Err(InitError(format!(
            concat![
                "Number of verifiers (got: {}) must be equal ",
                "to the number of parties in the key share (got: {})"
            ],
            verifiers.len(),
            key_share.num_parties()
        )));
    }

    let scalar_message = Scalar::from_reduced_bytes(prehashed_message);

    let context = interactive_signing::Context {
        key_share: key_share.clone(),
        message: scalar_message,
    };

    Session::new::<interactive_signing::Round1<P>>(
        rng,
        shared_randomness,
        signer,
        key_share.party_index(),
        verifiers,
        context,
    )
}
