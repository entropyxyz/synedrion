mod auxiliary;
mod error;
mod generic;
mod interactive_signing;
mod keygen;
mod presigning;
mod signing;

pub use auxiliary::AuxiliaryState;
pub use error::{Error, MyFault, TheirFault};
pub use generic::{Session, ToSend};
pub use interactive_signing::InteractiveSigningState;
pub use keygen::KeygenState;
pub use presigning::PresigningState;
pub use signing::SigningState;

use alloc::string::String;

use rand_core::CryptoRngCore;

use crate::protocols::common::{KeyShare, SessionId};
use crate::tools::group::Scalar;
use crate::SchemeParams;

pub type PrehashedMessage = [u8; 32];

pub fn make_interactive_signing_session<P: SchemeParams>(
    rng: &mut impl CryptoRngCore,
    key_share: &KeyShare<P>,
    prehashed_message: &PrehashedMessage,
) -> Result<Session<InteractiveSigningState<P>>, String> {
    let scalar_message = Scalar::try_from_reduced_bytes(prehashed_message)?;

    let session_id = SessionId::random(rng);
    let context = (key_share.clone(), scalar_message);

    Ok(Session::<InteractiveSigningState<P>>::new(
        rng,
        &session_id,
        key_share.num_parties(),
        key_share.party_index(),
        &context,
    ))
}
