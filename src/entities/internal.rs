use alloc::collections::BTreeSet;

use manul::protocol::PartyId;
use serde::{Deserialize, Serialize};

use crate::{
    params::{chain_scheme_params, SchemeParams},
    tools::hashing::{Chain, HashOutput, Hasher},
};

/// The session identifier (see Remark 4.1 in the paper).
///
/// The session identifier is tied to the identity of the parties, the mathematical parameters, and the public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Sid(HashOutput);

impl Sid {
    pub fn new<P: SchemeParams, Id: PartyId>(shared_randomness: &[u8], ids: &BTreeSet<Id>) -> Self {
        let digest = Hasher::<P::Digest>::new_with_dst(b"SID");
        let digest = chain_scheme_params::<P, _>(digest);
        let digest = digest.chain(&shared_randomness).chain(&ids);

        Self(digest.finalize(P::SECURITY_BITS))
    }
}
