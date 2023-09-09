use core::ops::Mul;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{PaillierParams, PublicKeyPaillierPrecomputed, SecretKeyPaillierPrecomputed};
use crate::tools::hashing::{Chain, Hashable};
use crate::uint::{pow_octo_signed, pow_wide_signed, Pow, Retrieve, Signed, UintModLike};

pub(crate) struct RPSecret<P: PaillierParams>(P::DoubleUint);

impl<P: PaillierParams> RPSecret<P> {
    pub fn random(rng: &mut impl CryptoRngCore, sk: &SecretKeyPaillierPrecomputed<P>) -> Self {
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
#[derive(Debug, Clone)]
pub(crate) struct RPParamsMod<P: PaillierParams> {
    pub(crate) pk: PublicKeyPaillierPrecomputed<P>,
    /// The ring-Pedersen base.
    pub(crate) base: P::DoubleUintMod, // $t$
    /// The ring-Pedersen power (a number belonging to the group produced by the base).
    pub(crate) power: P::DoubleUintMod, // $s$
}

impl<P: PaillierParams> RPParamsMod<P> {
    pub fn random(rng: &mut impl CryptoRngCore, sk: &SecretKeyPaillierPrecomputed<P>) -> Self {
        let secret = RPSecret::random(rng, sk);
        Self::random_with_secret(rng, &secret, sk.public_key())
    }

    pub fn public_key(&self) -> &PublicKeyPaillierPrecomputed<P> {
        &self.pk
    }

    pub fn random_with_secret(
        rng: &mut impl CryptoRngCore,
        secret: &RPSecret<P>,
        pk: &PublicKeyPaillierPrecomputed<P>,
    ) -> Self {
        let r = pk.random_invertible_group_elem(rng);

        let base = r.square();
        let power = base.pow(&secret.0);

        Self {
            pk: pk.clone(),
            base,
            power,
        }
    }

    /// Creates a commitment for `secret` with the randomizer `randomizer`.
    ///
    /// Both will be effectively reduced modulo `totient(N)`
    /// (that is, commitments produced for `x` and `x + totient(N)` are equal).
    // TODO: swap randomizer and secret?
    // - this will match the order for Ciphertext,
    // - this will match the order in the paper
    pub fn commit(
        &self,
        randomizer: &Signed<P::QuadUint>,
        secret: &Signed<P::DoubleUint>,
    ) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(pow_wide_signed(&self.base, randomizer) * self.power.pow_signed(secret))
    }

    pub fn commit_wide(
        &self,
        randomizer: &Signed<P::QuadUint>,
        secret: &Signed<P::QuadUint>,
    ) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(
            pow_wide_signed(&self.base, randomizer) * pow_wide_signed(&self.power, secret),
        )
    }

    pub fn commit_octo(
        &self,
        randomizer: &Signed<P::OctoUint>,
        secret: &P::DoubleUint,
    ) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(pow_octo_signed(&self.base, randomizer) * self.power.pow(secret))
    }

    pub fn commit_base_octo(&self, randomizer: &Signed<P::OctoUint>) -> RPCommitmentMod<P> {
        // $t^\rho mod N$ where $\rho$ is the randomizer.
        RPCommitmentMod(pow_octo_signed(&self.base, randomizer))
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
    pub fn to_mod(&self, pk: &PublicKeyPaillierPrecomputed<P>) -> RPParamsMod<P> {
        // TODO: check that the base and the power are within the modulus?
        RPParamsMod {
            pk: pk.clone(),
            base: P::DoubleUintMod::new(&self.base, pk.precomputed_modulus()),
            power: P::DoubleUintMod::new(&self.power, pk.precomputed_modulus()),
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

    pub fn pow_signed_wide(&self, exponent: &Signed<P::QuadUint>) -> Self {
        Self(pow_wide_signed(&self.0, exponent))
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
    pub fn to_mod(&self, pk: &PublicKeyPaillierPrecomputed<P>) -> RPCommitmentMod<P> {
        // TODO: check that `self.0` is within the modulus?
        RPCommitmentMod(P::DoubleUintMod::new(&self.0, pk.precomputed_modulus()))
    }
}
