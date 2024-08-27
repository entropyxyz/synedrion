use core::ops::Mul;

use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use super::{PaillierParams, PublicKeyPaillierPrecomputed, SecretKeyPaillierPrecomputed};
use crate::uint::{Bounded, Retrieve, Signed, UintLike, UintModLike};

pub(crate) struct RPSecret<P: PaillierParams>(Bounded<P::Uint>);

impl<P: PaillierParams> RPSecret<P> {
    pub fn random(rng: &mut impl CryptoRngCore, sk: &SecretKeyPaillierPrecomputed<P>) -> Self {
        // The random value will be reduced modulo `phi(N)` implicitly
        // when used as an exponent modulo N later.
        // So we are sampling it from this range to begin with.
        Self(sk.random_field_elem(rng))
    }
}

impl<P: PaillierParams> AsRef<Bounded<P::Uint>> for RPSecret<P> {
    fn as_ref(&self) -> &Bounded<P::Uint> {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RPParamsMod<P: PaillierParams> {
    pub(crate) pk: PublicKeyPaillierPrecomputed<P>,
    /// The ring-Pedersen base.
    pub(crate) base: P::UintMod, // $t$
    /// The ring-Pedersen power (a number belonging to the group produced by the base).
    pub(crate) power: P::UintMod, // $s$
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
        let power = base.pow_bounded(&secret.0);

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
    // TODO (#81): swap randomizer and secret?
    // - this will match the order for Ciphertext,
    // - this will match the order in the paper
    pub fn commit(
        &self,
        secret: &SecretBox<Signed<P::Uint>>,
        randomizer: &Signed<P::WideUint>,
    ) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(
            self.base.pow_signed_wide(randomizer) * self.power.pow_signed(secret.expose_secret()),
        )
    }

    pub fn commit_wide(
        &self,
        // TODO(dp): @reviewers Question unrelated to the PR, just something I noticed: Why is the
        // `secret` a `P::WideUint` in this method but a `P::Uint` in `commit_xwide` below? Should
        // it be the same here? Or `P::ExtraWide` there? Maybe it's like it should, because while
        // `commit` and `commit_wide` take a `Signed` secret, `commit_xwide` takes a `Bounded`?
        secret: &SecretBox<Signed<P::WideUint>>,
        randomizer: &Signed<P::WideUint>,
    ) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(
            self.base.pow_signed_wide(randomizer)
                * self.power.pow_signed_wide(secret.expose_secret()),
        )
    }

    pub fn commit_xwide(
        &self,
        secret: &SecretBox<Bounded<P::Uint>>,
        randomizer: &Signed<P::ExtraWideUint>,
    ) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(
            self.base.pow_signed_extra_wide(randomizer)
                * self.power.pow_bounded(secret.expose_secret()),
        )
    }

    pub fn commit_base_xwide(&self, randomizer: &Signed<P::ExtraWideUint>) -> RPCommitmentMod<P> {
        // $t^\rho mod N$ where $\rho$ is the randomizer.
        RPCommitmentMod(self.base.pow_signed_extra_wide(randomizer))
    }

    pub fn retrieve(&self) -> RPParams<P> {
        RPParams {
            base: self.base.retrieve(),
            power: self.power.retrieve(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RPParams<P: PaillierParams> {
    /// The ring-Pedersen base.
    pub(crate) base: P::Uint, // $t$
    /// The ring-Pedersen power (a number belonging to the group produced by the base).
    pub(crate) power: P::Uint, // $s$
}

impl<P: PaillierParams> RPParams<P> {
    pub fn to_mod(&self, pk: &PublicKeyPaillierPrecomputed<P>) -> RPParamsMod<P> {
        RPParamsMod {
            pk: pk.clone(),
            base: self.base.to_mod(pk.precomputed_modulus()),
            power: self.power.to_mod(pk.precomputed_modulus()),
        }
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct RPCommitmentMod<P: PaillierParams>(P::UintMod);

impl<P: PaillierParams> RPCommitmentMod<P> {
    pub fn retrieve(&self) -> RPCommitment<P> {
        RPCommitment(self.0.retrieve())
    }

    /// Raise to the power of `exponent`.
    ///
    /// Note: this is variable time in `exponent`.
    /// `exponent` will be effectively reduced modulo `totient(N)`.
    pub fn pow_signed_vartime(&self, exponent: &Signed<P::Uint>) -> Self {
        Self(self.0.pow_signed_vartime(exponent))
    }

    pub fn pow_signed_wide(&self, exponent: &Signed<P::WideUint>) -> Self {
        Self(self.0.pow_signed_wide(exponent))
    }
}

impl<'a, P: PaillierParams> Mul<&'a RPCommitmentMod<P>> for &'a RPCommitmentMod<P> {
    type Output = RPCommitmentMod<P>;
    fn mul(self, rhs: &RPCommitmentMod<P>) -> Self::Output {
        RPCommitmentMod(self.0 * rhs.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RPCommitment<P: PaillierParams>(P::Uint);

impl<P: PaillierParams> RPCommitment<P> {
    pub fn to_mod(&self, pk: &PublicKeyPaillierPrecomputed<P>) -> RPCommitmentMod<P> {
        RPCommitmentMod(self.0.to_mod(pk.precomputed_modulus()))
    }
}
