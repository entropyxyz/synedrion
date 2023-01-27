use crypto_bigint::{Integer, NonZero, RandomMod};
use rand_core::OsRng;

use super::params::PaillierParams;
use super::uint::Uint;

pub struct SecretKeyPaillier<P: PaillierParams> {
    p: P::PrimeUint,
    q: P::PrimeUint,
}

impl<P: PaillierParams> SecretKeyPaillier<P> {
    pub fn random() -> Self {
        let p = P::PrimeUint::safe_prime();
        let q = P::PrimeUint::safe_prime();

        Self { p, q }
    }

    pub fn random_exponent(&self) -> P::FieldElement {
        let totient = NonZero::new(self.totient()).unwrap();
        P::FieldElement::random_mod(&mut OsRng, &totient)
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyPaillier<P: PaillierParams> {
    /// N
    modulus: P::FieldElement,
}

impl<P: PaillierParams> PublicKeyPaillier<P> {
    pub fn modulus(&self) -> P::FieldElement {
        self.modulus
    }
}

#[cfg(test)]
mod tests {
    use super::SecretKeyPaillier;
    use crate::paillier::PaillierTest;

    #[test]
    fn basics() {
        let sk = SecretKeyPaillier::<PaillierTest>::random();
        let _pk = sk.public_key();
    }
}
