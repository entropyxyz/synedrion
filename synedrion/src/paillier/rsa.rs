use crypto_bigint::{CheckedSub, Gcd, Integer, Monty, NonZero, Odd, RandomMod, Square};
use crypto_primes::RandomPrimeWithRng;
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::params::PaillierParams;
use crate::{
    tools::Secret,
    uint::{Bounded, HasWide, Signed},
};

fn random_paillier_blum_prime<P: PaillierParams>(rng: &mut impl CryptoRngCore) -> P::HalfUint {
    loop {
        let prime = P::HalfUint::generate_prime_with_rng(rng, P::PRIME_BITS);
        if prime.as_ref()[0].0 & 3 == 3 {
            return prime;
        }
    }
}

/// The minimized structure containing RSA primes.
///
/// Both primes are 3 mod 4 (but are not necessarily safe primes).
///
/// Suitable for serialization or transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SecretPrimesWire<P: PaillierParams> {
    p: Secret<P::HalfUint>,
    q: Secret<P::HalfUint>,
}

impl<P: PaillierParams> SecretPrimesWire<P> {
    /// A single constructor to check the invariants
    fn new(p: Secret<P::HalfUint>, q: Secret<P::HalfUint>) -> Self {
        debug_assert!(p.expose_secret().as_ref()[0].0 & 3 == 3, "p must be 3 mod 4");
        debug_assert!(q.expose_secret().as_ref()[0].0 & 3 == 3, "q must be 3 mod 4");
        Self { p, q }
    }

    /// Creates the primes for a Paillier-Blum modulus,
    /// that is `p` and `q` are regular primes with an additional condition `p, q mod 3 = 4`.
    pub fn random_paillier_blum(rng: &mut impl CryptoRngCore) -> Self {
        Self::new(
            SecretBox::init_with(|| random_paillier_blum_prime::<P>(rng)).into(),
            SecretBox::init_with(|| random_paillier_blum_prime::<P>(rng)).into(),
        )
    }

    /// Creates a pair of safe primes.
    pub fn random_safe(rng: &mut impl CryptoRngCore) -> Self {
        Self::new(
            SecretBox::init_with(|| P::HalfUint::generate_safe_prime_with_rng(rng, P::PRIME_BITS)).into(),
            SecretBox::init_with(|| P::HalfUint::generate_safe_prime_with_rng(rng, P::PRIME_BITS)).into(),
        )
    }

    pub fn modulus(&self) -> PublicModulusWire<P> {
        PublicModulusWire::new(self)
    }

    pub fn into_precomputed(self) -> SecretPrimes<P> {
        SecretPrimes::new(self)
    }
}

/// RSA primes plus some precomputed constants.
#[derive(Debug, Clone)]
pub(crate) struct SecretPrimes<P: PaillierParams> {
    /// The base RSA primes corresponding to a modulus $N$.
    primes: SecretPrimesWire<P>,
    /// Euler's totient function of the modulus ($\phi(N)$).
    totient: Secret<P::Uint>,
}

impl<P: PaillierParams> SecretPrimes<P> {
    fn new(primes: SecretPrimesWire<P>) -> Self {
        let one = <P::HalfUint as Integer>::one();

        let p_minus_one = primes
            .p
            .expose_secret()
            .checked_sub(&one)
            .expect("`p` is prime, so greater than one");
        let q_minus_one = primes
            .q
            .expose_secret()
            .checked_sub(&one)
            .expect("`q` is prime, so greater than one");

        // Euler's totient function of $N = p q$ - the number of positive integers up to $N$
        // that are relatively prime to it.
        // Since $p$ and $q$ are primes, $\phi(N) = (p - 1) (q - 1)$.
        let totient = SecretBox::init_with(|| p_minus_one.mul_wide(&q_minus_one)).into();

        Self { primes, totient }
    }

    pub fn into_wire(self) -> SecretPrimesWire<P> {
        self.primes
    }

    pub fn modulus_wire(&self) -> PublicModulusWire<P> {
        PublicModulusWire::new(&self.primes)
    }

    pub fn p_half(&self) -> &SecretBox<P::HalfUint> {
        &self.primes.p
    }

    pub fn q_half(&self) -> &SecretBox<P::HalfUint> {
        &self.primes.q
    }

    pub fn p_half_odd(&self) -> SecretBox<Odd<P::HalfUint>> {
        SecretBox::init_with(|| Odd::new(*self.primes.p.expose_secret()).expect("`p` is an odd prime"))
    }

    pub fn q_half_odd(&self) -> SecretBox<Odd<P::HalfUint>> {
        SecretBox::init_with(|| Odd::new(*self.primes.q.expose_secret()).expect("`q` is an odd prime"))
    }

    pub fn p(&self) -> SecretBox<P::Uint> {
        SecretBox::init_with(|| {
            let mut p = *self.primes.p.expose_secret();
            let p_wide = p.into_wide();
            p.zeroize();
            p_wide
        })
    }

    pub fn q(&self) -> SecretBox<P::Uint> {
        SecretBox::init_with(|| {
            let mut q = *self.primes.q.expose_secret();
            let q_wide = q.into_wide();
            q.zeroize();
            q_wide
        })
    }

    pub fn p_signed(&self) -> SecretBox<Signed<P::Uint>> {
        SecretBox::init_with(|| {
            Signed::new_positive(*self.p().expose_secret(), P::PRIME_BITS).expect("`P::PRIME_BITS` is valid")
        })
    }

    pub fn q_signed(&self) -> SecretBox<Signed<P::Uint>> {
        SecretBox::init_with(|| {
            Signed::new_positive(*self.q().expose_secret(), P::PRIME_BITS).expect("`P::PRIME_BITS` is valid")
        })
    }

    pub fn p_nonzero(&self) -> SecretBox<NonZero<P::Uint>> {
        SecretBox::init_with(|| NonZero::new(*self.p().expose_secret()).expect("`p` is non-zero"))
    }

    pub fn q_nonzero(&self) -> SecretBox<NonZero<P::Uint>> {
        SecretBox::init_with(|| NonZero::new(*self.q().expose_secret()).expect("`q` is non-zero"))
    }

    pub fn p_wide_signed(&self) -> SecretBox<Signed<P::WideUint>> {
        SecretBox::init_with(|| self.p_signed().expose_secret().into_wide())
    }

    pub fn totient(&self) -> &SecretBox<P::Uint> {
        &self.totient
    }

    pub fn totient_bounded(&self) -> SecretBox<Bounded<P::Uint>> {
        SecretBox::init_with(|| {
            Bounded::new(*self.totient.expose_secret(), P::MODULUS_BITS).expect("`P::MODULUS_BITS` is valid")
        })
    }

    pub fn totient_wide_bounded(&self) -> SecretBox<Bounded<P::WideUint>> {
        SecretBox::init_with(|| self.totient_bounded().expose_secret().into_wide())
    }

    pub fn totient_nonzero(&self) -> SecretBox<NonZero<P::Uint>> {
        SecretBox::init_with(|| {
            NonZero::new(*self.totient.expose_secret()).expect(concat![
                "φ(n) is never zero for n >= 1; n is strictly greater than 1 ",
                "because it is (p-1)(q-1) and given that both p and q are prime ",
                "they are both strictly greater than 1"
            ])
        })
    }

    /// Returns a random in range `[0, \phi(N))`.
    pub fn random_residue_mod_totient(&self, rng: &mut impl CryptoRngCore) -> Bounded<P::Uint> {
        Bounded::new(
            P::Uint::random_mod(rng, self.totient_nonzero().expose_secret()),
            P::MODULUS_BITS,
        )
        .expect(concat![
            "the totient is smaller than the modulus, ",
            "and thefore can be bounded by 2^MODULUS_BITS"
        ])
    }
}

/// The minimized structure containing the public RSA modulus.
///
/// Suitable for serialization or transmission.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PublicModulusWire<P: PaillierParams>(P::Uint);

impl<P: PaillierParams> PublicModulusWire<P> {
    fn new(primes: &SecretPrimesWire<P>) -> Self {
        Self(primes.p.expose_secret().mul_wide(primes.q.expose_secret()))
    }

    pub fn modulus(&self) -> &P::Uint {
        &self.0
    }

    pub fn into_precomputed(self) -> PublicModulus<P> {
        PublicModulus::new(self)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PublicModulus<P: PaillierParams> {
    /// The base RSA modulus $N$.
    modulus: PublicModulusWire<P>,
    /// Montgomery representation parameters for modulo $N$.
    monty_params_mod_n: <P::UintMod as Monty>::Params,
}

impl<P: PaillierParams> PartialEq for PublicModulus<P> {
    fn eq(&self, other: &PublicModulus<P>) -> bool {
        // Only compare the moduli themselves, not the precomputed constants.
        self.modulus.eq(&other.modulus)
    }
}

impl<P: PaillierParams> Eq for PublicModulus<P> {}

impl<P: PaillierParams> PublicModulus<P> {
    pub fn new(modulus: PublicModulusWire<P>) -> Self {
        let odd_modulus = Odd::new(modulus.0).expect("the RSA modulus is odd");
        let monty_params_mod_n = P::UintMod::new_params_vartime(odd_modulus);
        Self {
            modulus,
            monty_params_mod_n,
        }
    }

    pub fn to_wire(&self) -> PublicModulusWire<P> {
        self.modulus.clone()
    }

    pub fn modulus(&self) -> &P::Uint {
        &self.modulus.0
    }

    pub fn modulus_nonzero(&self) -> NonZero<P::Uint> {
        NonZero::new(self.modulus.0).expect("the modulus is non-zero")
    }

    pub fn modulus_bounded(&self) -> Bounded<P::Uint> {
        Bounded::new(self.modulus.0, P::MODULUS_BITS).expect("the modulus can be bounded by 2^MODULUS_BITS")
    }

    pub fn monty_params_mod_n(&self) -> &<P::UintMod as Monty>::Params {
        &self.monty_params_mod_n
    }

    /// Returns a uniformly chosen number in range $[0, N)$ such that it is invertible modulo $N$, in Montgomery form.
    pub fn random_invertible_residue(&self, rng: &mut impl CryptoRngCore) -> P::UintMod {
        let modulus = self.modulus_nonzero();
        loop {
            let r = P::Uint::random_mod(rng, &modulus);
            if r.gcd(&self.modulus.0) == P::Uint::one() {
                return P::UintMod::new(r, self.monty_params_mod_n.clone());
            }
        }
    }

    /// Returns a uniformly chosen quadratic residue modulo $N$, in Montgomery form.
    pub fn random_quadratic_residue(&self, rng: &mut impl CryptoRngCore) -> P::UintMod {
        self.random_invertible_residue(rng).square()
    }
}
