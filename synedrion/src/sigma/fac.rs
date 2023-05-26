use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::paillier::{PaillierParams, SecretKeyPaillier};
use crate::tools::hashing::Hashable;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct FacProof<P: PaillierParams>(PhantomData<P>);

impl<P: PaillierParams> FacProof<P> {
    pub fn random(
        _rng: &mut impl CryptoRngCore,
        _sk: &SecretKeyPaillier<P>,
        _aux: &impl Hashable,
    ) -> Self {
        Self(PhantomData)
    }

    pub fn verify(&self) -> bool {
        true
    }
}
