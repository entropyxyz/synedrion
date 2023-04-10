use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::paillier::{Ciphertext, PaillierParams, PublicKeyPaillier};
use crate::tools::group::{Point, Scalar};
use crate::tools::hashing::Hashable;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicKeyPaillier<P>: Serialize"))]
#[serde(bound(deserialize = "PublicKeyPaillier<P>: for<'x> Deserialize<'x>"))]
pub(crate) struct LogStarProof<P: PaillierParams>(PublicKeyPaillier<P>);

impl<P: PaillierParams> LogStarProof<P> {
    pub fn random(
        _rng: &mut (impl RngCore + CryptoRng),
        _secret: &Scalar,            // `x`
        _randomizer: &P::DoubleUint, // `\rho`
        pk: &PublicKeyPaillier<P>,   // `N_0`
        _ciphertext: &Ciphertext<P>, // `C = enc(x, rho)`
        _base: &Point,               // `g`
        _power: &Point,              // `X = g^x`
        _aux: &impl Hashable,        // CHECK: used to derive `\hat{N}, s, t`
    ) -> Self {
        Self(pk.clone())
    }

    pub fn verify(
        &self,
        pk: &PublicKeyPaillier<P>,
        _ciphertext: &Ciphertext<P>,
        _base: &Point,
        _power: &Point,
        _aux: &impl Hashable,
    ) -> bool {
        &self.0 == pk
    }
}
