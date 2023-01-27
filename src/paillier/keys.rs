use crypto_bigint::{Integer, NonZero, RandomMod};
use rand_core::{CryptoRng, RngCore};

use super::params::PaillierParams;
use super::uint::Uint;

pub struct SecretKeyPaillier<P: PaillierParams> {
    p: P::PrimeUint,
    q: P::PrimeUint,
}

impl<P: PaillierParams> SecretKeyPaillier<P> {
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let p = P::PrimeUint::safe_prime_with_rng(rng);
        let q = P::PrimeUint::safe_prime_with_rng(rng);

        Self { p, q }
    }

    pub fn random_exponent(&self, rng: &mut (impl RngCore + CryptoRng)) -> P::FieldElement {
        let totient = NonZero::new(self.totient()).unwrap();
        P::FieldElement::random_mod(rng, &totient)
    }

    /// Euler's totient function of `p * q` - the number of positive integers up to `p * q`
    /// that are relatively prime to it.
    /// Since `p` and `q` are primes, returns `(p - 1) * (q - 1)`.
    pub fn totient(&self) -> P::FieldElement {
        P::mul_to_field_elem(
            &self.p.sub(&P::PrimeUint::ONE),
            &self.q.sub(&P::PrimeUint::ONE),
        )
    }

    pub fn public_key(&self) -> PublicKeyPaillier<P> {
        PublicKeyPaillier {
            modulus: P::mul_to_field_elem(&self.p, &self.q),
        }
    }

    pub fn random_field_elem(&self, rng: &mut (impl RngCore + CryptoRng)) -> P::FieldElement {
        let totient = self.totient();
        P::FieldElement::random_mod(rng, &NonZero::new(totient).unwrap())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyPaillier<P: PaillierParams> {
    /// N
    modulus: P::FieldElement,
}

impl<P: PaillierParams> PublicKeyPaillier<P> {
    pub fn random_group_elem(&self, rng: &mut (impl RngCore + CryptoRng)) -> P::GroupElement {
        let r = P::FieldElement::random_mod(rng, &NonZero::new(self.modulus).unwrap());
        P::field_elem_to_group_elem(&r, &self.modulus)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::SecretKeyPaillier;
    use crate::paillier::PaillierTest;

    #[test]
    fn basics() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let _pk = sk.public_key();
    }
}
