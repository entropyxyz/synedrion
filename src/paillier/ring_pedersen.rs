/// Implements the Definition 3.3 from the CGGMP'21 paper and related operations.
use core::ops::Mul;

use crypto_bigint::{modular::Retrieve, Integer, Monty, NonZero, RandomMod, ShrVartime};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    rsa::{PublicModulus, PublicModulusWire, SecretPrimes, SecretPrimesWire},
    PaillierParams,
};
use crate::{
    tools::{
        hashing::{Chain, Hashable},
        Secret,
    },
    uint::{Exponentiable, PublicUint, SecretUnsigned, ToMontgomery},
};

/// Ring-Pedersen secret.
#[derive(Debug, Clone)]
pub(crate) struct RPSecret<P: PaillierParams> {
    primes: SecretPrimes<P>,
    lambda: SecretUnsigned<P::Uint>,
}

impl<P: PaillierParams> RPSecret<P> {
    #[cfg(test)]
    pub fn random_small(rng: &mut dyn CryptoRngCore) -> Self {
        let primes = SecretPrimesWire::<P>::random_small_safe(rng).into_precomputed();
        let bound = NonZero::new(primes.totient().expose_secret().wrapping_shr_vartime(2))
            .expect("totient / 4 is still non-zero because p, q >= 5");
        let lambda = SecretUnsigned::new(
            Secret::init_with(|| P::Uint::random_mod(rng, &bound)),
            P::MODULUS_BITS - 2,
        )
        .expect("totient < N < 2^MODULUS_BITS, so totient / 4 < 2^(MODULUS_BITS - 2)");

        Self { primes, lambda }
    }

    pub fn random(rng: &mut dyn CryptoRngCore) -> Self {
        let primes = SecretPrimesWire::<P>::random_safe(rng).into_precomputed();

        let bound = Secret::init_with(|| {
            NonZero::new(primes.totient().expose_secret().wrapping_shr_vartime(2))
                .expect("totient / 4 is still non-zero because p, q >= 5")
        });
        let lambda = SecretUnsigned::new(
            Secret::init_with(|| P::Uint::random_mod(rng, bound.expose_secret())),
            P::MODULUS_BITS - 2,
        )
        .expect("totient < N < 2^MODULUS_BITS, so totient / 4 < 2^(MODULUS_BITS - 2)");

        Self { primes, lambda }
    }

    pub fn lambda(&self) -> &SecretUnsigned<P::Uint> {
        &self.lambda
    }

    pub fn random_residue_mod_totient(&self, rng: &mut dyn CryptoRngCore) -> SecretUnsigned<P::Uint> {
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
    base_randomizer: <P::Uint as Integer>::Monty, // $t$
    /// The ring-Pedersen base for secret exponentiation
    /// (a number belonging to the group produced by the randomizer base).
    base_value: <P::Uint as Integer>::Monty, // $s = t^\lambda$, where $\lambda$ is the secret
}

impl<P: PaillierParams> RPParams<P> {
    #[cfg(test)]
    pub fn random_small(rng: &mut dyn CryptoRngCore) -> Self {
        let secret = RPSecret::random_small(rng);
        Self::random_with_secret(rng, &secret)
    }

    pub fn random(rng: &mut dyn CryptoRngCore) -> Self {
        let secret = RPSecret::random(rng);
        Self::random_with_secret(rng, &secret)
    }

    pub fn random_with_secret(rng: &mut dyn CryptoRngCore, secret: &RPSecret<P>) -> Self {
        let modulus = secret.primes.modulus_wire().into_precomputed();

        let base_randomizer = modulus.random_quadratic_residue(rng); // $t$
        let base_value = base_randomizer.pow(&secret.lambda); // $s$

        Self {
            modulus,
            base_randomizer,
            base_value,
        }
    }

    pub fn base_randomizer(&self) -> &<P::Uint as Integer>::Monty {
        &self.base_randomizer
    }

    pub fn base_value(&self) -> &<P::Uint as Integer>::Monty {
        &self.base_value
    }

    pub fn modulus(&self) -> &P::Uint {
        self.modulus.modulus()
    }

    pub fn monty_params_mod_n(&self) -> &<<P::Uint as Integer>::Monty as Monty>::Params {
        self.modulus.monty_params_mod_n()
    }

    /// Creates a commitment for a secret `value` with a secret `randomizer`.
    pub fn commit<V, R>(&self, value: &V, randomizer: &R) -> RPCommitment<P>
    where
        <P::Uint as Integer>::Monty: Exponentiable<V> + Exponentiable<R>,
    {
        RPCommitment(self.base_value.pow(value) * self.base_randomizer.pow(randomizer))
    }

    /// Creates a commitment for a secret `randomizer` and the value 0.
    pub fn commit_zero_value<R>(&self, randomizer: &R) -> RPCommitment<P>
    where
        <P::Uint as Integer>::Monty: Exponentiable<R>,
    {
        RPCommitment(self.base_randomizer.pow(randomizer))
    }

    /// Creates a commitment for a secret `randomizer` and the value 0.
    pub fn commit_zero_randomizer<R>(&self, value: &R) -> RPCommitment<P>
    where
        <P::Uint as Integer>::Monty: Exponentiable<R>,
    {
        RPCommitment(self.base_value.pow(value))
    }

    pub fn to_wire(&self) -> RPParamsWire<P> {
        RPParamsWire {
            modulus: self.modulus.to_wire(),
            base_randomizer: self.base_randomizer.retrieve().into(),
            base_value: self.base_value.retrieve().into(),
        }
    }
}

impl<P: PaillierParams> Hashable for RPParams<P> {
    fn chain<C>(&self, chain: C) -> C
    where
        C: Chain,
    {
        chain.chain(&self.to_wire())
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
    base_randomizer: PublicUint<P::Uint>, // $t$
    /// The ring-Pedersen base for secret exponentiation
    /// (a number belonging to the group produced by the randomizer base).
    base_value: PublicUint<P::Uint>, // $s = t^\lambda$, where $\lambda$ is the secret
}

impl<P: PaillierParams> RPParamsWire<P> {
    pub fn modulus(&self) -> &P::Uint {
        self.modulus.modulus()
    }

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

impl<P: PaillierParams> Hashable for RPParamsWire<P> {
    fn chain<C>(&self, chain: C) -> C
    where
        C: Chain,
    {
        chain.chain_bytes(b"RPParamsWire").chain_serializable(self)
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct RPCommitment<P: PaillierParams>(<P::Uint as Integer>::Monty);

impl<P: PaillierParams> RPCommitment<P> {
    pub fn to_wire(&self) -> RPCommitmentWire<P> {
        RPCommitmentWire(self.0.retrieve().into())
    }

    /// Raise to the power of `exponent`.
    pub fn pow<V>(&self, exponent: &V) -> Self
    where
        <P::Uint as Integer>::Monty: Exponentiable<V>,
    {
        Self(self.0.pow(exponent))
    }
}

impl<'a, P: PaillierParams> Mul<&'a RPCommitment<P>> for &'a RPCommitment<P> {
    type Output = RPCommitment<P>;
    fn mul(self, rhs: &RPCommitment<P>) -> Self::Output {
        RPCommitment(self.0 * rhs.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RPCommitmentWire<P: PaillierParams>(PublicUint<P::Uint>);

impl<P: PaillierParams> RPCommitmentWire<P> {
    pub fn to_precomputed(&self, params: &RPParams<P>) -> RPCommitment<P> {
        RPCommitment(self.0.to_montgomery(params.monty_params_mod_n()))
    }
}

impl<P: PaillierParams> Hashable for RPCommitmentWire<P> {
    fn chain<C>(&self, chain: C) -> C
    where
        C: Chain,
    {
        chain.chain_bytes(b"RPCommitmentWire").chain_serializable(self)
    }
}
