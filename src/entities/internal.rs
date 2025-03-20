use alloc::collections::BTreeSet;

use manul::protocol::PartyId;
use serde::{Deserialize, Serialize};

use crate::{
    params::SchemeParams,
    tools::hashing::{Chain, HashOutput, Hasher},
};

/// The session identifier (see Remark 4.1 in the paper).
///
/// The session identifier is tied to the identity of the parties, the mathematical parameters, and the public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Sid(HashOutput);

impl Sid {
    pub fn new<P: SchemeParams, Id: PartyId>(shared_randomness: &[u8], ids: &BTreeSet<Id>) -> Self {
        Self(
            Hasher::<P>::new_with_dst(b"SID")
                .chain_type::<P::Curve>()
                .chain(&shared_randomness)
                .chain(&ids)
                .finalize(),
        )
    }
}
