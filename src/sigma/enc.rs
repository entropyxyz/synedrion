use core::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::paillier::{Ciphertext, PaillierParams, PublicKeyPaillier};
use crate::tools::group::Scalar;
use crate::tools::hashing::Hashable;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct EncProof<P: PaillierParams>(PhantomData<P>);

impl<P: PaillierParams> EncProof<P> {
    pub fn random(
        _rng: &mut (impl RngCore + CryptoRng),
        _pk: &PublicKeyPaillier<P>,
        _secret: &Scalar,
        _randomizer: &P::DoubleUint,
        _ciphertext: &Ciphertext<P>,
        _aux: &impl Hashable,
    ) -> Self {
        Self(PhantomData)
    }

    pub fn verify(&self) -> bool {
        true
    }
}
