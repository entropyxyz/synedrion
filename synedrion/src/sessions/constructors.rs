use alloc::format;
use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::{
    hazmat::{PrehashVerifier, RandomizedPrehashSigner},
    Keypair,
};

use super::error::LocalError;
use super::states::Session;
use crate::cggmp21::{
    interactive_signing, key_gen, key_refresh, InteractiveSigningResult, KeyRefreshResult,
    KeyShare, KeygenAndAuxResult, SchemeParams,
};
use crate::curve::Scalar;

/// Prehashed message to sign.
pub type PrehashedMessage = [u8; 32];

/// Creates the initial state for the joined KeyGen and KeyRefresh+Auxiliary protocols.
pub fn make_keygen_and_aux_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
) -> Result<Session<KeygenAndAuxResult<P>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig> + Debug + Clone + Ord,
{
    Session::new::<key_gen::Round1<P>>(rng, shared_randomness, signer, verifiers, ())
}

/// Creates the initial state for the KeyRefresh+Auxiliary protocol.
pub fn make_key_refresh_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
) -> Result<Session<KeyRefreshResult<P>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig> + Debug + Clone + Ord,
{
    Session::new::<key_refresh::Round1<P>>(rng, shared_randomness, signer, verifiers, ())
}

/// Creates the initial state for the joined Presigning and Signing protocols.
pub fn make_interactive_signing_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
    key_share: &KeyShare<P>,
    prehashed_message: &PrehashedMessage,
) -> Result<Session<InteractiveSigningResult<P>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig> + Debug + Clone + Ord,
{
    // TODO (#68): check that key share party index corresponds to the signer's position
    // among the verifiers
    if verifiers.len() != key_share.num_parties() {
        return Err(LocalError(format!(
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
        verifiers,
        context,
    )
}
