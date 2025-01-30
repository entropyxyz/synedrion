/// Implements the Definition 3.3 from the CGGMP'21 paper and related operations.
use core::ops::Mul;

use crypto_bigint::{
    modular::Retrieve, subtle::ConditionallySelectable, Bounded, Integer, Invert, Monty, MultiExponentiateBoundedExp,
    NonZero, RandomMod, ShrVartime,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{
    rsa::{PublicModulus, PublicModulusWire, SecretPrimes, SecretPrimesWire},
    PaillierParams,
};
use crate::{
    tools::Secret,
    uint::{Exponentiable, HasWide, PublicSigned, SecretSigned, SecretUnsigned, ToMontgomery},
};

/// Ring-Pedersen secret.
#[derive(Debug, Clone)]
pub(crate) struct RPSecret<P: PaillierParams> {
    primes: SecretPrimes<P>,
    lambda: SecretUnsigned<P::Uint>,
}

impl<P: PaillierParams> RPSecret<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
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

    pub fn random_residue_mod_totient(&self, rng: &mut impl CryptoRngCore) -> SecretUnsigned<P::Uint> {
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
        let base_value = base_randomizer.pow(&secret.lambda); // $s$

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

    pub fn monty_params_mod_n(&self) -> &<P::UintMod as Monty>::Params {
        self.modulus.monty_params_mod_n()
    }

    /// Creates a commitment for a public `value` with a `randomizer` where the `randomizer` is twice the size of the `value`.
    pub fn commit_pub_mixed<E>(&self, value: &PublicSigned<E>, randomizer: &PublicSigned<E::Wide>) -> RPCommitment<P>
    where
        E: HasWide + Bounded,
        <E as HasWide>::Wide: Integer + Bounded + Zeroize + ConditionallySelectable,
        P::UintMod: MultiExponentiateBoundedExp<E::Wide, [(P::UintMod, E::Wide); 2]>,
    {
        let signs = (value.is_negative(), randomizer.is_negative());

        let r = randomizer.abs();
        let v = value.abs().to_wide();

        self.commit(signs, v, r, randomizer.bound())
    }

    /// Creates a commitment for a secret `value` with a `randomizer` where the `randomizer` is twice the size of the `value`.
    pub fn commit_secret_mixed<E>(&self, value: &SecretSigned<E>, randomizer: &SecretSigned<E::Wide>) -> RPCommitment<P>
    where
        E: Integer + Bounded + Zeroize + ConditionallySelectable,
        E: HasWide,
        <E as HasWide>::Wide: Integer + Bounded + Zeroize + ConditionallySelectable,
        P::UintMod: MultiExponentiateBoundedExp<E::Wide, [(P::UintMod, E::Wide); 2]>,
    {
        let signs = (bool::from(value.is_negative()), bool::from(randomizer.is_negative()));

        let r = *randomizer.abs_value().expose_secret();
        let v = value.abs_value().expose_secret().to_wide();

        self.commit(signs, v, r, randomizer.bound())
    }

    /// Creates a commitment for a secret `value` with a `randomizer`.
    pub fn commit_secret<E>(&self, value: &SecretSigned<E>, randomizer: &SecretSigned<E>) -> RPCommitment<P>
    where
        E: Integer + Bounded + Zeroize + ConditionallySelectable,
        P::UintMod: MultiExponentiateBoundedExp<E, [(P::UintMod, E); 2]>,
    {
        let signs = (bool::from(value.is_negative()), bool::from(randomizer.is_negative()));

        let r = *randomizer.abs_value().expose_secret();
        let v = *value.abs_value().expose_secret();

        self.commit(signs, v, r, randomizer.bound())
    }

    /// Creates a commitment for a secret `value` with a `randomizer`.
    pub fn commit_pub<E>(&self, value: &PublicSigned<E>, randomizer: &PublicSigned<E>) -> RPCommitment<P>
    where
        E: Integer + Bounded,
        P::UintMod: MultiExponentiateBoundedExp<E, [(P::UintMod, E); 2]>,
    {
        let signs = (value.is_negative(), randomizer.is_negative());

        let r = randomizer.abs();
        let v = value.abs();

        self.commit(signs, v, r, randomizer.bound())
    }

    /// Creates a commitment for a secret `randomizer` and the value 0.
    pub fn commit_zero<R>(&self, randomizer: &R) -> RPCommitment<P>
    where
        P::UintMod: Exponentiable<R>,
    {
        RPCommitment(self.base_randomizer.pow(randomizer))
    }

    pub fn to_wire(&self) -> RPParamsWire<P> {
        RPParamsWire {
            modulus: self.modulus.to_wire(),
            base_randomizer: self.base_randomizer.retrieve(),
            base_value: self.base_value.retrieve(),
        }
    }

    #[inline]
    fn bases_and_exponents<I>(&self, signs: (bool, bool), v: I, r: I) -> [(P::UintMod, I); 2] {
        match signs {
            (true, true) => {
                // both negative => multi-exp and then invert
                [(self.base_value, v), (self.base_randomizer, r)]
            }
            (true, false) => {
                // v neg, r pos => invert self.base_value, then multi-exp
                [
                    (self.base_value.invert_vartime().expect("TODO(dp): justify this"), v),
                    (self.base_randomizer, r),
                ]
            }
            (false, false) => {
                // both positive => multi-exp
                [(self.base_value, v), (self.base_randomizer, r)]
            }
            (false, true) => {
                // v pos, r neg => invert self.base_randomizer, then multi-exp
                [
                    (self.base_value, v),
                    (
                        self.base_randomizer.invert_vartime().expect("TODO(dp): justify this"),
                        r,
                    ),
                ]
            }
        }
    }

    #[inline]
    fn commit<E>(&self, signs: (bool, bool), v: E, r: E, bound: u32) -> RPCommitment<P>
    where
        P::UintMod: MultiExponentiateBoundedExp<E, [(P::UintMod, E); 2]>,
    {
        let bases_and_exponents = self.bases_and_exponents(signs, v, r);
        let mut commitment = P::UintMod::multi_exponentiate_bounded_exp(&bases_and_exponents, bound);
        // If both exponents are negative, we can do the exponentiation with the absolute values and then invert in the end.
        if signs == (true, true) {
            commitment = commitment.invert_vartime().expect("TODO(dp): justify this")
        }
        RPCommitment(commitment)
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
    pub fn pow<V>(&self, exponent: &V) -> Self
    where
        P::UintMod: Exponentiable<V>,
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
pub(crate) struct RPCommitmentWire<P: PaillierParams>(P::Uint);

impl<P: PaillierParams> RPCommitmentWire<P> {
    pub fn to_precomputed(&self, params: &RPParams<P>) -> RPCommitment<P> {
        RPCommitment(self.0.to_montgomery(params.monty_params_mod_n()))
    }
}
