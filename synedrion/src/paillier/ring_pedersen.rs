use core::ops::Mul;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{PaillierParams, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::hashing::{Chain, Hashable};
use crate::uint::{pow_wide_signed, Pow, Retrieve, Signed, UintModLike};

pub(crate) struct RPSecret<P: PaillierParams>(P::DoubleUint);

impl<P: PaillierParams> RPSecret<P> {
    pub fn random(rng: &mut impl CryptoRngCore, sk: &SecretKeyPaillier<P>) -> Self {
        // CHECK: `lambda` will be reduced modulo phi(N) implicitly
        // when used as an exponent modulo N later.
        // So can we just sample a random modulo N, or modulo the whole size of Uint instead?
        // This way we won't need the secret key here.
        Self(sk.random_field_elem(rng))
    }
}

impl<P: PaillierParams> AsRef<P::DoubleUint> for RPSecret<P> {
    fn as_ref(&self) -> &P::DoubleUint {
        &self.0
    }
}

// TODO: should this struct have Paillier public key bundled?
pub(crate) struct RPParamsMod<P: PaillierParams> {
    /// The ring-Pedersen base.
    pub(crate) base: P::DoubleUintMod, // $t$
    /// The ring-Pedersen power (a number belonging to the group produced by the base).
    pub(crate) power: P::DoubleUintMod, // $s$
}

impl<P: PaillierParams> RPParamsMod<P> {
    pub fn random(rng: &mut impl CryptoRngCore, sk: &SecretKeyPaillier<P>) -> Self {
        let secret = RPSecret::random(rng, sk);
        Self::random_with_secret(rng, &secret, &sk.public_key())
    }

    pub fn random_with_secret(
        rng: &mut impl CryptoRngCore,
        secret: &RPSecret<P>,
        pk: &PublicKeyPaillier<P>,
    ) -> Self {
        let r = pk.random_invertible_group_elem(rng);

        // TODO: use `square()` when it's available
        let base = r * r;
        let power = base.pow(&secret.0);

        Self { base, power }
    }

    /// Creates a commitment for `secret` with the randomizer `randomizer`.
    ///
    /// Both will be effectively reduced modulo `totient(N)`
    /// (that is, commitments produced for `x` and `x + totient(N)` are equal).
    pub fn commit(
        &self,
        randomizer: &Signed<P::QuadUint>,
        secret: &Signed<P::DoubleUint>,
    ) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(pow_wide_signed(&self.base, randomizer) * self.power.pow_signed(secret))
    }

    pub fn retrieve(&self) -> RPParams<P> {
        RPParams {
            base: self.base.retrieve(),
            power: self.power.retrieve(),
        }
    }
}

// TODO: should this struct have Paillier public key bundled?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RPParams<P: PaillierParams> {
    /// The ring-Pedersen base.
    pub(crate) base: P::DoubleUint, // $t$
    /// The ring-Pedersen power (a number belonging to the group produced by the base).
    pub(crate) power: P::DoubleUint, // $s$
}

impl<P: PaillierParams> RPParams<P> {
    pub fn to_mod(&self, pk: &PublicKeyPaillier<P>) -> RPParamsMod<P> {
        // TODO: check that the base and the power are within the modulus?
        RPParamsMod {
            base: P::DoubleUintMod::new(&self.base, &pk.modulus()),
            power: P::DoubleUintMod::new(&self.power, &pk.modulus()),
        }
    }
}

impl<P: PaillierParams> Hashable for RPParams<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.base).chain(&self.power)
    }
}

// TODO: should this struct have Paillier public key bundled?
#[derive(PartialEq, Eq)]
pub(crate) struct RPCommitmentMod<P: PaillierParams>(P::DoubleUintMod);

impl<P: PaillierParams> RPCommitmentMod<P> {
    pub fn retrieve(&self) -> RPCommitment<P> {
        RPCommitment(self.0.retrieve())
    }

    /// Raise to the power of `exponent`.
    ///
    /// `exponent` will be effectively reduced modulo `totient(N)`.
    pub fn pow_signed(&self, exponent: &Signed<P::DoubleUint>) -> Self {
        Self(self.0.pow_signed(exponent))
    }
}

impl<'a, P: PaillierParams> Mul<&'a RPCommitmentMod<P>> for &'a RPCommitmentMod<P> {
    type Output = RPCommitmentMod<P>;
    fn mul(self, rhs: &RPCommitmentMod<P>) -> Self::Output {
        RPCommitmentMod(self.0 * rhs.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RPCommitment<P: PaillierParams>(P::DoubleUint);

impl<P: PaillierParams> RPCommitment<P> {
    pub fn to_mod(&self, pk: &PublicKeyPaillier<P>) -> RPCommitmentMod<P> {
        // TODO: check that `self.0` is within the modulus?
        RPCommitmentMod(P::DoubleUintMod::new(&self.0, &pk.modulus()))
    }
}
