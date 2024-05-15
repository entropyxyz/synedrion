use alloc::format;
use alloc::vec::Vec;
use core::fmt::Debug;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::{
    hazmat::{PrehashVerifier, RandomizedPrehashSigner},
    Keypair,
};

use crate::cggmp21::{
    interactive_signing, key_gen, key_init, key_refresh, InteractiveSigningResult, KeyGenResult,
    KeyInitResult, KeyRefreshResult, SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::entities::{KeyShare, ThresholdKeyShareSeed};
use crate::rounds::PartyIdx;
use crate::sessions::{LocalError, Session};
use crate::www02::{self, KeyResharingResult};

/// Prehashed message to sign.
pub type PrehashedMessage = [u8; 32];

/// Creates the initial state for the joined KeyGen and KeyRefresh+Auxiliary protocols.
pub fn make_key_init_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
) -> Result<Session<KeyInitResult, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig> + Debug + Clone + Ord,
{
    Session::new::<key_init::Round1<P>>(rng, shared_randomness, signer, verifiers, ())
}

/// Creates the initial state for the joined KeyGen and KeyRefresh+Auxiliary protocols.
pub fn make_key_gen_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
) -> Result<Session<KeyGenResult<P>, Sig, Signer, Verifier>, LocalError>
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
    key_share: &KeyShare<P, Verifier>,
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

    let inputs = interactive_signing::Inputs {
        key_share: key_share.map_verifiers(verifiers),
        message: scalar_message,
    };

    Session::new::<interactive_signing::Round1<P>>(
        rng,
        shared_randomness,
        signer,
        verifiers,
        inputs,
    )
}

/// Old share data.
#[derive(Clone)]
pub struct OldHolder<P: SchemeParams, V: Ord> {
    /// The threshold key share.
    pub key_share_seed: ThresholdKeyShareSeed<P, V>,
}

/// New share data.
#[derive(Clone)]
pub struct NewHolder<Verifier> {
    /// The verifying key the old shares add up to.
    pub verifying_key: VerifyingKey,
    /// The old threshold.
    pub old_threshold: usize,
    /// The list of holders of the old shares (order not important).
    pub old_holders: Vec<Verifier>,
}

/// Inputs for the Key Resharing protocol.
#[derive(Clone)]
pub struct KeyResharingInputs<P: SchemeParams, Verifier: Ord> {
    /// Old share data if the node holds it, or `None`.
    pub old_holder: Option<OldHolder<P, Verifier>>,
    /// New share data if the node is one of the new holders, or `None`.
    pub new_holder: Option<NewHolder<Verifier>>,
    /// A list of new holders of the shares (order not important).
    pub new_holders: Vec<Verifier>,
    /// The new threshold.
    pub new_threshold: usize,
}

/// Creates the initial state for the Key Resharing protocol.
pub fn make_key_resharing_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
    inputs: &KeyResharingInputs<P, Verifier>,
) -> Result<Session<KeyResharingResult<P>, Sig, Signer, Verifier>, LocalError>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig> + Debug + Clone + Ord,
{
    let new_holder = inputs
        .new_holder
        .as_ref()
        .map(|new_holder| {
            let old_holders = new_holder
                .old_holders
                .iter()
                .map(|verifier| {
                    verifiers
                        .iter()
                        .position(|v| v == verifier)
                        .map(PartyIdx::from_usize)
                        .ok_or(LocalError(
                            "Cannot find a given old holder in the list of verifiers".into(),
                        ))
                })
                .collect::<Result<Vec<_>, LocalError>>()?;
            Ok(www02::NewHolder {
                verifying_key: Point::from_verifying_key(&new_holder.verifying_key),
                old_threshold: new_holder.old_threshold,
                old_holders,
            })
        })
        .transpose()?;

    let old_holder = inputs
        .old_holder
        .as_ref()
        .map(|old_holder| www02::OldHolder {
            key_share_seed: old_holder.key_share_seed.map_verifiers(verifiers),
        });

    let new_holders = inputs
        .new_holders
        .iter()
        .map(|verifier| {
            verifiers
                .iter()
                .position(|v| v == verifier)
                .map(PartyIdx::from_usize)
                .ok_or(LocalError(
                    "Cannot find a given new holder in the list of verifiers".into(),
                ))
        })
        .collect::<Result<Vec<_>, LocalError>>()?;

    let context = www02::KeyResharingContext {
        old_holder,
        new_holder,
        new_holders,
        new_threshold: inputs.new_threshold,
    };
    Session::new::<www02::Round1<P>>(rng, shared_randomness, signer, verifiers, context)
}
