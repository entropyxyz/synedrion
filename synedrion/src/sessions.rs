pub(crate) mod error;
mod generic;
pub(crate) mod signed_message;
//mod broadcast;

use alloc::string::String;

use rand_core::CryptoRngCore;
use signature::hazmat::{PrehashSigner, PrehashVerifier};

use crate::curve::{RecoverableSignature, Scalar};
use crate::protocols::common::{KeyShare, SessionId};
use crate::protocols::interactive_signing;
use crate::SchemeParams;

pub use error::Error;
pub use generic::{Session, ToSend};
pub use signed_message::SignedMessage;

pub type PrehashedMessage = [u8; 32];

pub fn make_interactive_signing_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    signer: &Signer,
    verifiers: &[Verifier],
    key_share: &KeyShare<P>,
    prehashed_message: &PrehashedMessage,
) -> Result<Session<RecoverableSignature, Sig, Signer, Verifier>, String>
where
    P: SchemeParams + 'static,
    Signer: PrehashSigner<Sig> + Clone,
    Verifier: PrehashVerifier<Sig> + Clone,
{
    let scalar_message = Scalar::try_from_reduced_bytes(prehashed_message)?;

    let session_id = SessionId::random(rng);
    let context = interactive_signing::Context {
        session_id,
        key_share: key_share.clone(),
        message: scalar_message,
    };

    Ok(Session::new::<interactive_signing::Round1Part1<P>>(
        rng,
        signer,
        key_share.party_index(),
        verifiers,
        &context,
    ))
}
