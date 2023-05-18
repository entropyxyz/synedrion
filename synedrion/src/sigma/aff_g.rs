use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::paillier::{Ciphertext, PaillierParams, PublicKeyPaillier};
use crate::tools::group::{Point, Scalar};
use crate::tools::hashing::Hashable;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicKeyPaillier<P>: Serialize"))]
#[serde(bound(deserialize = "PublicKeyPaillier<P>: for<'x> Deserialize<'x>"))]
pub(crate) struct AffGProof<P: PaillierParams> {
    pk0: PublicKeyPaillier<P>,
    pk1: PublicKeyPaillier<P>,
}

impl<P: PaillierParams> AffGProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn random(
        _rng: &mut (impl RngCore + CryptoRng),
        _x: &Scalar,
        // CHECK: technically, it's something in range `\mathcal{J}`
        // CHECK: judging by how it is used in the protocols, we may need to take `-y`
        // (because the proof is for the affine transformation `x * z + y`,
        // but it is applied to the affine transformation `x * z - y`)
        _y: &Scalar,
        _rho: &P::DoubleUint,   // in range of the modulus from `pk0`
        _rho_y: &P::DoubleUint, // in range of the modulus from `pk1`
        pk0: &PublicKeyPaillier<P>,
        pk1: &PublicKeyPaillier<P>,
        _capital_c: &Ciphertext<P>, // a ciphertext encrypted with `pk0`
        _capital_d: &Ciphertext<P>, // where `D = C [*] x [+] enc_pk0(y, rho)` ([*] and [+]) are homomorphic operations
        _capital_y: &Ciphertext<P>, // where `Y = enc_pk1(y, rho_y)`
        _capital_x: &Point,         // where `X = g * x`, where `g` is the curve generator
        _aux: &impl Hashable,       // CHECK: used to derive `\hat{N}, s, t`
    ) -> Self {
        Self {
            pk0: pk0.clone(),
            pk1: pk1.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        pk0: &PublicKeyPaillier<P>,
        pk1: &PublicKeyPaillier<P>,
        _capital_c: &Ciphertext<P>,
        _capital_d: &Ciphertext<P>,
        _capital_y: &Ciphertext<P>,
        _capital_x: &Point,
        _aux: &impl Hashable, // CHECK: used to derive `\hat{N}, s, t`
    ) -> bool {
        &self.pk0 == pk0 && &self.pk1 == pk1
    }
}
