mod auxiliary;
mod error;
mod generic;
mod interactive_signing;
mod keygen;
mod presigning;
mod signed_message;
mod signing;

pub use auxiliary::AuxiliaryState;
pub use error::{Error, MyFault, TheirFault};
pub use generic::{Session, ToSend};
pub use interactive_signing::InteractiveSigningState;
pub use keygen::KeygenState;
pub use presigning::PresigningState;
pub use signed_message::SignedMessage;
pub use signing::SigningState;

use alloc::string::String;

use rand_core::CryptoRngCore;
use signature::{
    hazmat::{PrehashSigner, PrehashVerifier},
    SignatureEncoding,
};

use crate::curve::Scalar;
use crate::protocols::common::{KeyShare, SessionId};
use crate::SchemeParams;

pub type PrehashedMessage = [u8; 32];

pub fn make_interactive_signing_session<P, Sig, Signer, Verifier>(
    rng: &mut impl CryptoRngCore,
    signer: &Signer,
    verifiers: &[Verifier],
    key_share: &KeyShare<P>,
    prehashed_message: &PrehashedMessage,
) -> Result<Session<InteractiveSigningState<P>, Sig, Signer, Verifier>, String>
where
    P: SchemeParams,
    Signer: PrehashSigner<Sig> + Clone,
    Verifier: PrehashVerifier<Sig> + Clone,
    Sig: SignatureEncoding + for<'a> TryFrom<&'a [u8]>,
    for<'a> <Sig as TryFrom<&'a [u8]>>::Error: core::fmt::Display,
{
    let scalar_message = Scalar::try_from_reduced_bytes(prehashed_message)?;

    let session_id = SessionId::random(rng);
    let context = (key_share.clone(), scalar_message);

    Ok(Session::new(
        rng,
        signer,
        verifiers,
        &session_id,
        key_share.num_parties(),
        key_share.party_index(),
        &context,
    ))
}
