/// Implements the Definition 3.3 from the CGGMP'21 paper and related operations.
use core::ops::Mul;

use crypto_bigint::{Monty, NonZero, RandomMod, ShrVartime};
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use super::{
    rsa::{PublicModulus, PublicModulusPrecomputed, SecretPrimes, SecretPrimesPrecomputed},
    PaillierParams,
};
use crate::{
    tools::Secret,
    uint::{Bounded, Exponentiable, Retrieve, Signed, ToMontgomery},
};

#[derive(Debug, Clone)]
pub(crate) struct RPSecret<P: PaillierParams> {
    primes: SecretPrimesPrecomputed<P>,
    lambda: Secret<Bounded<P::Uint>>,
}

impl<P: PaillierParams> RPSecret<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let primes = SecretPrimes::<P>::random_safe(rng).into_precomputed();

        // The random value will be reduced modulo `phi(N)` implicitly
        // when used as an exponent modulo N later.
        // So we are sampling it from this range to begin with.

        let bound = SecretBox::init_with(|| {
            NonZero::new(primes.totient().expose_secret().wrapping_shr_vartime(2))
                .expect("totient / 4 is still non-zero because p, q >= 5")
        });
        let lambda = SecretBox::init_with(|| {
            Bounded::new(
                P::Uint::random_mod(rng, bound.expose_secret()),
                P::MODULUS_BITS as u32 - 2,
            )
            .expect("totient < N < 2^MODULUS_BITS, so totient / 4 < 2^(MODULUS_BITS - 2)")
        })
        .into();

        Self { primes, lambda }
    }

    pub fn lambda(&self) -> &SecretBox<Bounded<P::Uint>> {
        &self.lambda
    }

    pub fn random_field_elem(&self, rng: &mut impl CryptoRngCore) -> Bounded<P::Uint> {
        self.primes.random_field_elem(rng)
    }

    pub fn totient_nonzero(&self) -> SecretBox<NonZero<P::Uint>> {
        self.primes.totient_nonzero()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RPParamsMod<P: PaillierParams> {
    /// The public modulus $\hat{N}$
    precomputed_modulus: PublicModulusPrecomputed<P>,
    /// The ring-Pedersen base.
    base: P::UintMod, // $t$
    /// The ring-Pedersen power (a number belonging to the group produced by the base).
    power: P::UintMod, // $s = t^\lambda$, where $\lambda$ is the secret
}

impl<P: PaillierParams> RPParamsMod<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let secret = RPSecret::random(rng);
        Self::random_with_secret(rng, &secret)
    }

    pub fn random_with_secret(rng: &mut impl CryptoRngCore, secret: &RPSecret<P>) -> Self {
        let precomputed_modulus = secret.primes.modulus().into_precomputed();

        let base = precomputed_modulus.random_square_group_elem(rng); // $t$
        let power = base.pow_bounded(secret.lambda.expose_secret()); // $s$

        Self {
            precomputed_modulus,
            base,
            power,
        }
    }

    pub fn base(&self) -> &P::UintMod {
        &self.base
    }

    pub fn power(&self) -> &P::UintMod {
        &self.power
    }

    pub fn modulus_bounded(&self) -> Bounded<P::Uint> {
        self.precomputed_modulus.modulus_bounded()
    }

    pub fn monty_params_mod_n(&self) -> &<P::UintMod as Monty>::Params {
        self.precomputed_modulus.monty_params_mod_n()
    }

    /// Creates a commitment for `secret` with the randomizer `randomizer`.
    ///
    /// Both will be effectively reduced modulo `totient(N)`
    /// (that is, commitments produced for `x` and `x + totient(N)` are equal).
    // TODO (#81): swap randomizer and secret?
    // - this will match the order for Ciphertext,
    // - this will match the order in the paper
    pub fn commit(&self, secret: &Signed<P::Uint>, randomizer: &Signed<P::WideUint>) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(self.base.pow_signed_wide(randomizer) * self.power.pow_signed(secret))
    }

    pub fn commit_wide(&self, secret: &Signed<P::WideUint>, randomizer: &Signed<P::WideUint>) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(self.base.pow_signed_wide(randomizer) * self.power.pow_signed_wide(secret))
    }

    pub fn commit_xwide(
        &self,
        secret: &SecretBox<Bounded<P::Uint>>,
        randomizer: &Signed<P::ExtraWideUint>,
    ) -> RPCommitmentMod<P> {
        // $t^\rho * s^m mod N$ where $\rho$ is the randomizer and $m$ is the secret.
        RPCommitmentMod(self.base.pow_signed_extra_wide(randomizer) * self.power.pow_bounded(secret.expose_secret()))
    }

    pub fn commit_base_xwide(&self, randomizer: &Signed<P::ExtraWideUint>) -> RPCommitmentMod<P> {
        // $t^\rho mod N$ where $\rho$ is the randomizer.
        RPCommitmentMod(self.base.pow_signed_extra_wide(randomizer))
    }

    pub fn retrieve(&self) -> RPParams<P> {
        RPParams {
            modulus: self.precomputed_modulus.modulus().clone(),
            base: self.base.retrieve(),
            power: self.power.retrieve(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicModulus<P>: Serialize"))]
#[serde(bound(deserialize = "for<'x> PublicModulus<P>: Deserialize<'x>"))]
pub(crate) struct RPParams<P: PaillierParams> {
    /// The public modulus $\hat{N}$
    modulus: PublicModulus<P>,
    /// The ring-Pedersen base.
    base: P::Uint, // $t$
    /// The ring-Pedersen power (a number belonging to the group produced by the base).
    power: P::Uint, // $s$
}

impl<P: PaillierParams> RPParams<P> {
    pub fn to_mod(&self) -> RPParamsMod<P> {
        let precomputed_modulus = self.modulus.clone().into_precomputed();
        let base = self.base.to_montgomery(precomputed_modulus.monty_params_mod_n());
        let power = self.power.to_montgomery(precomputed_modulus.monty_params_mod_n());
        RPParamsMod {
            precomputed_modulus,
            base,
            power,
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
    pub fn to_mod(&self, params: &RPParamsMod<P>) -> RPCommitmentMod<P> {
        RPCommitmentMod(self.0.to_montgomery(params.precomputed_modulus.monty_params_mod_n()))
    }
}
