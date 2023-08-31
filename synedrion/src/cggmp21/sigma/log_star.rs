use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::curve::{Point, Scalar};
use crate::paillier::{Ciphertext, PaillierParams, PublicKeyPaillier};
use crate::tools::hashing::Hashable;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicKeyPaillier<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "PublicKeyPaillier<P::Paillier>: for<'x> Deserialize<'x>"))]
pub(crate) struct LogStarProof<P: SchemeParams>(PublicKeyPaillier<P::Paillier>);

impl<P: SchemeParams> LogStarProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn random(
        _rng: &mut impl CryptoRngCore,
        _secret: &Scalar,                                          // `x`
        _randomizer: &<P::Paillier as PaillierParams>::DoubleUint, // `\rho`
        pk: &PublicKeyPaillier<P::Paillier>,                       // `N_0`
        _ciphertext: &Ciphertext<P::Paillier>,                     // `C = enc(x, rho)`
        _base: &Point,                                             // `g`
        _power: &Point,                                            // `X = g^x`
        _aux: &impl Hashable, // CHECK: used to derive `\hat{N}, s, t`
    ) -> Self {
        Self(pk.clone())
    }

    pub fn verify(
        &self,
        pk: &PublicKeyPaillier<P::Paillier>,
        _ciphertext: &Ciphertext<P::Paillier>,
        _base: &Point,
        _power: &Point,
        _aux: &impl Hashable,
    ) -> bool {
        &self.0 == pk
    }
}
