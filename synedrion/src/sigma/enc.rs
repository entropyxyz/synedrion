use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::paillier::{Ciphertext, PaillierParams, PublicKeyPaillier};
use crate::tools::group::Scalar;
use crate::tools::hashing::Hashable;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicKeyPaillier<P>: Serialize"))]
#[serde(bound(deserialize = "PublicKeyPaillier<P>: for<'x> Deserialize<'x>"))]
pub(crate) struct EncProof<P: PaillierParams>(PublicKeyPaillier<P>);

impl<P: PaillierParams> EncProof<P> {
    pub fn random(
        _rng: &mut impl CryptoRngCore,
        _secret: &Scalar,            // `k`
        _randomizer: &P::DoubleUint, // `\rho`
        pk: &PublicKeyPaillier<P>,   // `N_0`
        _ciphertext: &Ciphertext<P>, // `K`
        _aux: &impl Hashable,        // CHECK: used to derive `\hat{N}, s, t`
    ) -> Self {
        Self(pk.clone())
    }

    pub fn verify(
        &self,
        pk: &PublicKeyPaillier<P>,   // `N_0`
        _ciphertext: &Ciphertext<P>, // `K`
        _aux: &impl Hashable,        // CHECK: used to derive `\hat{N}, s, t`
    ) -> bool {
        &self.0 == pk
    }
}
