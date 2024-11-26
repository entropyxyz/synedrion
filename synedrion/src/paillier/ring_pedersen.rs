/// Implements the Definition 3.3 from the CGGMP'21 paper and related operations.
use core::ops::Mul;

use crypto_bigint::{Monty, NonZero, RandomMod, ShrVartime};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    rsa::{PublicModulus, PublicModulusWire, SecretPrimes, SecretPrimesWire},
    PaillierParams,
};
use crate::{
    tools::Secret,
    uint::{Bounded, Exponentiable, Retrieve, Signed, ToMontgomery},
};

/// Ring-Pedersen secret.
#[derive(Debug, Clone)]
pub(crate) struct RPSecret<P: PaillierParams> {
    primes: SecretPrimes<P>,
    lambda: Secret<Bounded<P::Uint>>,
}

impl<P: PaillierParams> RPSecret<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let primes = SecretPrimesWire::<P>::random_safe(rng).into_precomputed();

        let bound = Secret::init_with(|| {
            NonZero::new(primes.totient().expose_secret().wrapping_shr_vartime(2))
                .expect("totient / 4 is still non-zero because p, q >= 5")
        });
        let lambda = Secret::init_with(|| {
            Bounded::new(P::Uint::random_mod(rng, bound.expose_secret()), P::MODULUS_BITS - 2)
                .expect("totient < N < 2^MODULUS_BITS, so totient / 4 < 2^(MODULUS_BITS - 2)")
        });

        Self { primes, lambda }
    }

    pub fn lambda(&self) -> &Secret<Bounded<P::Uint>> {
        &self.lambda
    }

    pub fn random_residue_mod_totient(&self, rng: &mut impl CryptoRngCore) -> Bounded<P::Uint> {
        self.primes.random_residue_mod_totient(rng)
    }

    pub fn totient_nonzero(&self) -> Secret<NonZero<P::Uint>> {
        self.primes.totient_nonzero()
    }

    pub fn modulus(&self) -> P::Uint {
        *self.primes.modulus_wire().modulus()
    }
}

/// The expanded representation of ring-Pedersen parameters.
///
/// All the necessary constants precomputed, suitable for usage in ZK proofs.
#[derive(Debug, Clone)]
pub(crate) struct RPParams<P: PaillierParams> {
    /// The public modulus $\hat{N}$
    modulus: PublicModulus<P>,
    /// The ring-Pedersen base for randomizer exponentiation.
    base_randomizer: P::UintMod, // $t$
    /// The ring-Pedersen base for secret exponentiation
    /// (a number belonging to the group produced by the randomizer base).
    base_value: P::UintMod, // $s = t^\lambda$, where $\lambda$ is the secret
}

impl<P: PaillierParams> RPParams<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let secret = RPSecret::random(rng);
        Self::random_with_secret(rng, &secret)
    }

    pub fn random_with_secret(rng: &mut impl CryptoRngCore, secret: &RPSecret<P>) -> Self {
        let modulus = secret.primes.modulus_wire().into_precomputed();

        let base_randomizer = modulus.random_quadratic_residue(rng); // $t$
        let base_value = base_randomizer.pow_bounded(secret.lambda.expose_secret()); // $s$

        Self {
            modulus,
            base_randomizer,
            base_value,
        }
    }

    pub fn base_randomizer(&self) -> &P::UintMod {
        &self.base_randomizer
    }

    pub fn base_value(&self) -> &P::UintMod {
        &self.base_value
    }

    pub fn modulus(&self) -> &P::Uint {
        self.modulus.modulus()
    }

    pub fn modulus_bounded(&self) -> Bounded<P::Uint> {
        self.modulus.modulus_bounded()
    }

    pub fn monty_params_mod_n(&self) -> &<P::UintMod as Monty>::Params {
        self.modulus.monty_params_mod_n()
    }

    /// Creates a commitment for a secret `value` with a secret `randomizer`.
    pub fn commit(&self, value: &Secret<Signed<P::Uint>>, randomizer: &Secret<Signed<P::WideUint>>) -> RPCommitment<P> {
        RPCommitment(
            self.base_value.pow_signed(value.expose_secret())
                * self.base_randomizer.pow_signed_wide(randomizer.expose_secret()),
        )
    }

    /// Creates a commitment for a secret `value` with a secret `randomizer`.
    pub fn commit_wide(
        &self,
        value: &Secret<Signed<P::WideUint>>,
        randomizer: &Secret<Signed<P::WideUint>>,
    ) -> RPCommitment<P> {
        RPCommitment(
            self.base_value.pow_signed_wide(value.expose_secret())
                * self.base_randomizer.pow_signed_wide(randomizer.expose_secret()),
        )
    }

    /// Creates a commitment for a secret `randomizer` and the value 0.
    pub fn commit_zero_xwide(&self, randomizer: &Secret<Signed<P::ExtraWideUint>>) -> RPCommitment<P> {
        RPCommitment(self.base_randomizer.pow_signed_extra_wide(randomizer.expose_secret()))
    }

    /// Creates a commitment for a public `value` with a public `randomizer`.
    pub fn commit_public(&self, value: &Signed<P::Uint>, randomizer: &Signed<P::WideUint>) -> RPCommitment<P> {
        RPCommitment(self.base_value.pow_signed(value) * self.base_randomizer.pow_signed_wide(randomizer))
    }

    /// Creates a commitment for a public `value` with a public `randomizer`.
    pub fn commit_public_wide(&self, value: &Signed<P::WideUint>, randomizer: &Signed<P::WideUint>) -> RPCommitment<P> {
        RPCommitment(self.base_value.pow_signed_wide(value) * self.base_randomizer.pow_signed_wide(randomizer))
    }

    /// Creates a commitment for a public `value` with a public `randomizer`.
    pub fn commit_public_xwide(
        &self,
        value: &Bounded<P::Uint>,
        randomizer: &Signed<P::ExtraWideUint>,
    ) -> RPCommitment<P> {
        RPCommitment(self.base_value.pow_bounded(value) * self.base_randomizer.pow_signed_extra_wide(randomizer))
    }

    /// Creates a commitment for a public `randomizer` and the value 0.
    pub fn commit_public_base_xwide(&self, randomizer: &Signed<P::ExtraWideUint>) -> RPCommitment<P> {
        RPCommitment(self.base_randomizer.pow_signed_extra_wide(randomizer))
    }

    pub fn to_wire(&self) -> RPParamsWire<P> {
        RPParamsWire {
            modulus: self.modulus.to_wire(),
            base_randomizer: self.base_randomizer.retrieve(),
            base_value: self.base_value.retrieve(),
        }
    }
}

/// Minimal public ring-Pedersen parameters suitable for serialization and transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicModulusWire<P>: Serialize"))]
#[serde(bound(deserialize = "for<'x> PublicModulusWire<P>: Deserialize<'x>"))]
pub(crate) struct RPParamsWire<P: PaillierParams> {
    /// The public modulus $\hat{N}$
    modulus: PublicModulusWire<P>,
    /// The ring-Pedersen base for randomizer exponentiation.
    base_randomizer: P::Uint, // $t$
    /// The ring-Pedersen base for secret exponentiation
    /// (a number belonging to the group produced by the randomizer base).
    base_value: P::Uint, // $s = t^\lambda$, where $\lambda$ is the secret
}

impl<P: PaillierParams> RPParamsWire<P> {
    pub fn to_precomputed(&self) -> RPParams<P> {
        let modulus = self.modulus.clone().into_precomputed();
        let base_randomizer = self.base_randomizer.to_montgomery(modulus.monty_params_mod_n());
        let base_value = self.base_value.to_montgomery(modulus.monty_params_mod_n());
        RPParams {
            modulus,
            base_randomizer,
            base_value,
        }
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct RPCommitment<P: PaillierParams>(P::UintMod);

impl<P: PaillierParams> RPCommitment<P> {
    pub fn to_wire(&self) -> RPCommitmentWire<P> {
        RPCommitmentWire(self.0.retrieve())
    }

    /// Raise to the power of `exponent`.
    ///
    /// Note: this is variable time in `exponent`.
    pub fn pow_signed_vartime(&self, exponent: &Signed<P::Uint>) -> Self {
        Self(self.0.pow_signed_vartime(exponent))
    }

    /// Raise to the power of `exponent`.
    ///
    /// Note: this is variable time in `exponent`.
    pub fn pow_signed_wide_vartime(&self, exponent: &Signed<P::WideUint>) -> Self {
        Self(self.0.pow_signed_wide_vartime(exponent))
    }

    /// Raise to the power of `exponent`.
    pub fn pow_signed_wide(&self, exponent: &Secret<Signed<P::WideUint>>) -> Self {
        Self(self.0.pow_signed_wide(exponent.expose_secret()))
    }
}

impl<'a, P: PaillierParams> Mul<&'a RPCommitment<P>> for &'a RPCommitment<P> {
    type Output = RPCommitment<P>;
    fn mul(self, rhs: &RPCommitment<P>) -> Self::Output {
        RPCommitment(self.0 * rhs.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RPCommitmentWire<P: PaillierParams>(P::Uint);

impl<P: PaillierParams> RPCommitmentWire<P> {
    pub fn to_precomputed(&self, params: &RPParams<P>) -> RPCommitment<P> {
        RPCommitment(self.0.to_montgomery(params.monty_params_mod_n()))
    }
}
