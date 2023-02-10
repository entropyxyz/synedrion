use crypto_bigint::{modular::Retrieve, Integer, Invert, NonZero, Pow, RandomMod, Zero};
use rand_core::{CryptoRng, RngCore};

use super::params::PaillierParams;
use super::uint::Uint;
use crate::tools::hashing::{Chain, HashEncoding, HashInto, Hashable, XofHash};

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

    pub fn rns_split(&self, elem: &P::FieldElement) -> (P::PrimeUintMod, P::PrimeUintMod) {
        let p_big: P::FieldElement = (P::PrimeUint::ZERO, self.p).into();
        let q_big: P::FieldElement = (P::PrimeUint::ZERO, self.q).into();
        let (_, p): (P::PrimeUint, P::PrimeUint) = (*elem % NonZero::new(p_big).unwrap()).into();
        let p = P::puint_to_puint_mod(&p, &self.p);
        let (_, q): (P::PrimeUint, P::PrimeUint) = (*elem % NonZero::new(q_big).unwrap()).into();
        let q = P::puint_to_puint_mod(&q, &self.q);
        (p, q)
    }

    pub fn rns_join(&self, rns: &(P::PrimeUintMod, P::PrimeUintMod)) -> P::FieldElement {
        let (p_part, q_part) = *rns;
        let pk = self.public_key();
        let p_big: P::FieldElement = (P::PrimeUint::ZERO, self.p).into();
        let q_big: P::FieldElement = (P::PrimeUint::ZERO, self.q).into();
        let pq_big = p_big.add(&q_big);
        let pq_m = P::field_elem_to_group_elem(&pq_big, &pk.modulus());
        let inv = pq_m.invert().unwrap();

        let p_part_big: P::FieldElement = (P::PrimeUint::ZERO, p_part.retrieve()).into();
        let q_part_big: P::FieldElement = (P::PrimeUint::ZERO, q_part.retrieve()).into();

        let p_big_m = P::field_elem_to_group_elem(&p_big, &pk.modulus());
        let q_big_m = P::field_elem_to_group_elem(&q_big, &pk.modulus());
        let p_part_m = P::field_elem_to_group_elem(&p_part_big, &pk.modulus());
        let q_part_m = P::field_elem_to_group_elem(&q_part_big, &pk.modulus());

        (inv * &(p_part_m * &q_big_m + q_part_m * &p_big_m)).retrieve()
    }

    fn sqrt_part(&self, x: &P::PrimeUintMod, modulus: &P::PrimeUint) -> Option<P::PrimeUintMod> {
        // Both `p` and `q` are safe primes, so they're 3 mod 4.
        // This means that if square root exists, it must be of the form `+/- x^((p+1)/4)`,
        // CHECK: can we get an overflow here?
        let candidate = x.pow(&(modulus.add(&P::PrimeUint::ONE) >> 2));
        if candidate * candidate == *x {
            Some(candidate)
        } else {
            None
        }
    }

    pub fn sqrt(
        &self,
        rns: &(P::PrimeUintMod, P::PrimeUintMod),
    ) -> Option<(P::PrimeUintMod, P::PrimeUintMod)> {
        let (p_part, q_part) = *rns;
        let p_res = self.sqrt_part(&p_part, &self.p);
        let q_res = self.sqrt_part(&q_part, &self.q);
        match (p_res, q_res) {
            (Some(p), Some(q)) => Some((p, q)),
            _ => None,
        }
    }

    pub fn inv_modulus(&self) -> P::FieldElement {
        let m = self.totient();
        let k = m.trailing_zeros();
        let m_odd = m >> k;
        let x = self.public_key().modulus();

        let (a, _) = x.inv_odd_mod(&m_odd);
        let b = x.inv_mod2k(k);

        // Restore from RNS:
        // x = a mod m_odd = b mod 2^k
        // => x = a + m_odd * ((b - a) * m_odd^(-1) mod 2^k)
        let m_odd_inv = m_odd.inv_mod2k(k);

        // This part is mod 2^k
        let t =
            b.sub(&a).mul(&m_odd_inv) & ((P::FieldElement::ONE << k).sub(&P::FieldElement::ONE));
        a.add(&m_odd.mul(&t))
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

    pub fn random_group_elem(&self, rng: &mut (impl RngCore + CryptoRng)) -> P::GroupElement {
        let r = P::FieldElement::random_mod(rng, &NonZero::new(self.modulus).unwrap());
        P::field_elem_to_group_elem(&r, &self.modulus)
    }

    pub fn random_invertible_group_elem(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> P::GroupElement {
        // TODO: is there a faster way? How many loops on average does it take?
        loop {
            let r = P::FieldElement::random_mod(rng, &NonZero::new(self.modulus).unwrap());
            let r_m = P::field_elem_to_group_elem(&r, &self.modulus);
            if r_m.invert().is_some().into() {
                return r_m;
            }
        }
    }

    pub fn random_group_elem_raw(&self, rng: &mut (impl RngCore + CryptoRng)) -> P::FieldElement {
        P::FieldElement::random_mod(rng, &NonZero::new(self.modulus).unwrap())
    }

    pub fn hash_to_group_elems_raw(&self, digest: XofHash, count: usize) -> Vec<P::FieldElement> {
        let mut reader = digest.finalize_reader();
        (0..count)
            .map(|_| {
                P::FieldElement::from_reader(&mut reader) % NonZero::new(self.modulus).unwrap()
            })
            .collect()
    }
}

impl<P: PaillierParams> Hashable for PublicKeyPaillier<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.modulus)
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
