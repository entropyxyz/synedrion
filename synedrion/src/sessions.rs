mod broadcast;
pub(crate) mod error;
pub(crate) mod signed_message;
mod states;
mod type_erased;

use alloc::string::String;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashSigner, PrehashVerifier};

use crate::curve::{RecoverableSignature, Scalar};
use crate::protocols::common::KeyShare;
use crate::protocols::interactive_signing;
use crate::SchemeParams;

pub use error::Error;
pub use signed_message::SignedMessage;
pub use states::{FinalizeOutcome, SendingState, ToSend};

pub type PrehashedMessage = [u8; 32];

pub fn make_interactive_signing_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    shared_randomness: &[u8],
    signer: Signer,
    verifiers: &[Verifier],
    key_share: &KeyShare<P>,
    prehashed_message: &PrehashedMessage,
) -> Result<SendingState<RecoverableSignature, Sig, Signer, Verifier>, String>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    P: SchemeParams + 'static,
    Signer: PrehashSigner<Sig>,
    Verifier: PrehashVerifier<Sig> + Clone,
{
    let scalar_message = Scalar::try_from_reduced_bytes(prehashed_message)?;

    let context = interactive_signing::Context {
        key_share: key_share.clone(),
        message: scalar_message,
    };

    Ok(SendingState::new::<interactive_signing::Round1Part1<P>>(
        rng,
        shared_randomness,
        signer,
        key_share.party_index(),
        verifiers,
        context,
    ))
}
