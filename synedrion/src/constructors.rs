use alloc::collections::BTreeSet;
use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::{
    hazmat::{PrehashVerifier, RandomizedPrehashSigner},
    Keypair,
};

use crate::cggmp21::{
    aux_gen, interactive_signing, key_gen, key_init, key_refresh, AuxGenResult, AuxInfo,
    InteractiveSigningResult, KeyGenResult, KeyInitResult, KeyRefreshResult, KeyShare,
    SchemeParams,
};
use crate::curve::Scalar;
use crate::sessions::{LocalError, Session, SessionId};
use crate::www02::{key_resharing, KeyResharingInputs, KeyResharingResult};

/// Prehashed message to sign.
pub type PrehashedMessage = [u8; 32];

/// Creates the initial state for the joined KeyGen and KeyRefresh+Auxiliary protocols.
pub fn make_key_init_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    session_id: SessionId,
    signer: Signer,
    verifiers: &BTreeSet<Verifier>,
) -> Result<Session<KeyInitResult<P, Verifier>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig>
        + Debug
        + Clone
        + Ord
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync
        + 'static,
{
    Session::new::<key_init::Round1<P, Verifier>>(rng, session_id, signer, verifiers, ())
}

/// Creates the initial state for the joined KeyGen and KeyRefresh+Auxiliary protocols.
pub fn make_key_gen_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    session_id: SessionId,
    signer: Signer,
    verifiers: &BTreeSet<Verifier>,
) -> Result<Session<KeyGenResult<P, Verifier>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig>
        + Debug
        + Clone
        + Ord
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync
        + 'static,
{
    Session::new::<key_gen::Round1<P, Verifier>>(rng, session_id, signer, verifiers, ())
}

/// Creates the initial state for the joined KeyGen and KeyRefresh+Auxiliary protocols.
pub fn make_aux_gen_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    session_id: SessionId,
    signer: Signer,
    verifiers: &BTreeSet<Verifier>,
) -> Result<Session<AuxGenResult<P, Verifier>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig>
        + Debug
        + Clone
        + Ord
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync
        + 'static,
{
    Session::new::<aux_gen::Round1<P, Verifier>>(rng, session_id, signer, verifiers, ())
}

/// Creates the initial state for the KeyRefresh+Auxiliary protocol.
pub fn make_key_refresh_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    session_id: SessionId,
    signer: Signer,
    verifiers: &BTreeSet<Verifier>,
) -> Result<Session<KeyRefreshResult<P, Verifier>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig>
        + Debug
        + Clone
        + Ord
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync
        + 'static,
{
    Session::new::<key_refresh::Round1<P, Verifier>>(rng, session_id, signer, verifiers, ())
}

/// Creates the initial state for the joined Presigning and Signing protocols.
pub fn make_interactive_signing_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    session_id: SessionId,
    signer: Signer,
    verifiers: &BTreeSet<Verifier>,
    key_share: &KeyShare<P, Verifier>,
    aux_info: &AuxInfo<P, Verifier>,
    prehashed_message: &PrehashedMessage,
) -> Result<Session<InteractiveSigningResult<P, Verifier>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig>
        + Debug
        + Clone
        + Ord
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync
        + 'static,
{
    // TODO (#68): check that key share and aux data owner corresponds to the signer
    if !verifiers.is_subset(&key_share.all_parties()) {
        return Err(LocalError(
            "The given verifiers are not a subset of the ones in the key share".into(),
        ));
    }

    let scalar_message = Scalar::from_reduced_bytes(prehashed_message);

    let inputs = interactive_signing::Inputs {
        key_share: key_share.clone(),
        aux_info: aux_info.clone(),
        message: scalar_message,
    };

    Session::new::<interactive_signing::Round1<P, Verifier>>(
        rng, session_id, signer, verifiers, inputs,
    )
}

/// Creates the initial state for the Key Resharing protocol.
pub fn make_key_resharing_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    session_id: SessionId,
    signer: Signer,
    verifiers: &BTreeSet<Verifier>,
    inputs: KeyResharingInputs<P, Verifier>,
) -> Result<Session<KeyResharingResult<P, Verifier>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig>
        + Debug
        + Clone
        + Ord
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync
        + 'static,
{
    let verifiers_set = BTreeSet::from_iter(verifiers.iter().cloned());

    if !inputs.new_holders.is_subset(&verifiers_set) {
        return Err(LocalError(
            "The new holders must be a subset of all parties".into(),
        ));
    }

    if let Some(new_holder) = inputs.new_holder.as_ref() {
        if !new_holder.old_holders.is_subset(&verifiers_set) {
            return Err(LocalError(
                "The old holders must be a subset of all parties".into(),
            ));
        }
    }

    Session::new::<key_resharing::Round1<P, Verifier>>(rng, session_id, signer, verifiers, inputs)
}
