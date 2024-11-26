use core::ops::Deref;

use crypto_bigint::{Monty, NonZero, Odd, RandomMod, Square};
use crypto_primes::RandomPrimeWithRng;
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::params::PaillierParams;
use crate::{
    tools::Secret,
    uint::{Bounded, CheckedSub, HasWide, Integer, Invert, Signed},
};

fn random_paillier_blum_prime<P: PaillierParams>(rng: &mut impl CryptoRngCore) -> P::HalfUint {
    loop {
        let prime = P::HalfUint::generate_prime_with_rng(rng, P::PRIME_BITS as u32);
        if prime.as_ref()[0].0 & 3 == 3 {
            return prime;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SecretPrimes<P: PaillierParams> {
    p: Secret<P::HalfUint>,
    q: Secret<P::HalfUint>,
}

impl<P: PaillierParams> SecretPrimes<P> {
    /// Creates the primes for a Paillier-Blum modulus,
    /// that is `p` and `q` are regular primes with an additional condition `p, q mod 3 = 4`.
    pub fn random_paillier_blum(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            p: SecretBox::init_with(|| random_paillier_blum_prime::<P>(rng)).into(),
            q: SecretBox::init_with(|| random_paillier_blum_prime::<P>(rng)).into(),
        }
    }

    /// Creates a pair of safe primes.
    pub fn random_safe(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            p: SecretBox::init_with(|| P::HalfUint::generate_safe_prime_with_rng(rng, P::PRIME_BITS as u32)).into(),
            q: SecretBox::init_with(|| P::HalfUint::generate_safe_prime_with_rng(rng, P::PRIME_BITS as u32)).into(),
        }
    }

    pub fn modulus(&self) -> PublicModulus<P> {
        PublicModulus::new(self)
    }

    pub fn into_precomputed(self) -> SecretPrimesPrecomputed<P> {
        SecretPrimesPrecomputed::new(self)
    }
}

// TODO: this should be ZeroizeOnDrop, but that needs support in crypto-bigint - Monty::Params are not Zeroize.
#[derive(Debug, Clone)]
pub(crate) struct SecretPrimesPrecomputed<P: PaillierParams> {
    /// The base RSA primes corresponding to a modulus $N$.
    primes: SecretPrimes<P>,
    /// Euler's totient function of the modulus ($\phi(N)$).
    totient: Secret<P::Uint>,
}

impl<P: PaillierParams> SecretPrimesPrecomputed<P> {
    pub fn new(primes: SecretPrimes<P>) -> Self {
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

    pub fn into_minimal(self) -> SecretPrimes<P> {
        self.primes
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
            Signed::new_positive(*self.p().expose_secret(), P::PRIME_BITS as u32).expect("`P::PRIME_BITS` is valid")
        })
    }

    pub fn q_signed(&self) -> SecretBox<Signed<P::Uint>> {
        SecretBox::init_with(|| {
            Signed::new_positive(*self.q().expose_secret(), P::PRIME_BITS as u32).expect("`P::PRIME_BITS` is valid")
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

    pub fn modulus(&self) -> PublicModulus<P> {
        PublicModulus::new(&self.primes)
    }

    pub fn totient(&self) -> &SecretBox<P::Uint> {
        &self.totient
    }

    pub fn totient_bounded(&self) -> SecretBox<Bounded<P::Uint>> {
        SecretBox::init_with(|| {
            Bounded::new(*self.totient.expose_secret(), P::MODULUS_BITS as u32).expect("`P::MODULUS_BITS` is valid")
        })
    }

    pub fn totient_wide_bounded(&self) -> SecretBox<Bounded<P::WideUint>> {
        SecretBox::init_with(|| self.totient_bounded().expose_secret().into_wide())
    }

    /// Returns Euler's totient function (`φ(n)`) of the modulus as a [`NonZero`].
    pub fn totient_nonzero(&self) -> SecretBox<NonZero<P::Uint>> {
        SecretBox::init_with(|| {
            NonZero::new(*self.totient.expose_secret()).expect(concat![
                "φ(n) is never zero for n >= 1; n is strictly greater than 1 ",
                "because it is (p-1)(q-1) and given that both p and q are prime ",
                "they are both strictly greater than 1"
            ])
        })
    }

    pub fn random_field_elem(&self, rng: &mut impl CryptoRngCore) -> Bounded<P::Uint> {
        Bounded::new(
            P::Uint::random_mod(rng, self.totient_nonzero().expose_secret()),
            P::MODULUS_BITS as u32,
        )
        .expect(concat![
            "the totient is smaller than the modulus, ",
            "and thefore can be bounded by 2^MODULUS_BITS"
        ])
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PublicModulus<P: PaillierParams>(P::Uint);

impl<P: PaillierParams> PublicModulus<P> {
    pub fn new(primes: &SecretPrimes<P>) -> Self {
        Self(primes.p.expose_secret().mul_wide(primes.q.expose_secret()))
    }

    pub fn into_precomputed(self) -> PublicModulusPrecomputed<P> {
        PublicModulusPrecomputed::new(self)
    }
}

impl<P: PaillierParams> Deref for PublicModulus<P> {
    type Target = P::Uint;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PublicModulusPrecomputed<P: PaillierParams> {
    /// The base RSA modulus $N$.
    modulus: PublicModulus<P>,
    /// Montgomery representation parameters for modulo $N$.
    monty_params_mod_n: <P::UintMod as Monty>::Params,
}

impl<P: PaillierParams> PartialEq for PublicModulusPrecomputed<P> {
    fn eq(&self, other: &PublicModulusPrecomputed<P>) -> bool {
        self.modulus.eq(&other.modulus)
    }
}

impl<P: PaillierParams> Eq for PublicModulusPrecomputed<P> {}

impl<P: PaillierParams> PublicModulusPrecomputed<P> {
    pub fn new(modulus: PublicModulus<P>) -> Self {
        let odd_modulus = Odd::new(*modulus).expect("the RSA modulus is odd");
        let monty_params_mod_n = P::UintMod::new_params_vartime(odd_modulus);
        Self {
            modulus,
            monty_params_mod_n,
        }
    }

    pub fn into_minimal(self) -> PublicModulus<P> {
        self.modulus
    }

    pub fn modulus(&self) -> &PublicModulus<P> {
        &self.modulus
    }

    pub fn modulus_nonzero(&self) -> NonZero<P::Uint> {
        NonZero::new(*self.modulus).expect("the modulus is non-zero")
    }

    pub fn modulus_bounded(&self) -> Bounded<P::Uint> {
        Bounded::new(*self.modulus, P::MODULUS_BITS as u32).expect("the modulus can be bounded by 2^MODULUS_BITS")
    }

    pub fn monty_params_mod_n(&self) -> &<P::UintMod as Monty>::Params {
        &self.monty_params_mod_n
    }

    /// Finds an invertible group element via rejection sampling. Returns the
    /// element in Montgomery form.
    pub fn random_invertible_group_elem(&self, rng: &mut impl CryptoRngCore) -> P::UintMod {
        let modulus = self.modulus_nonzero();
        loop {
            let r = P::Uint::random_mod(rng, &modulus);
            let r_m = P::UintMod::new(r, self.monty_params_mod_n.clone());
            if r_m.invert().is_some().into() {
                return r_m;
            }
        }
    }

    /// Returns a uniformly chosen quadratic residue modulo $N$.
    pub fn random_square_group_elem(&self, rng: &mut impl CryptoRngCore) -> P::UintMod {
        self.random_invertible_group_elem(rng).square()
    }
}
