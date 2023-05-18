use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::params::PaillierParams;
use super::uint::{
    CheckedAdd, CheckedMul, CheckedSub, HasWide, Integer, Invert, NonZero, Pow, RandomMod,
    RandomPrimeWithRng, Retrieve, UintLike, UintModLike,
};
use crate::tools::hashing::{Chain, Hashable};

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKeyPaillier<P: PaillierParams> {
    p: P::SingleUint,
    q: P::SingleUint,
}

impl<P: PaillierParams> SecretKeyPaillier<P> {
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let p = P::SingleUint::generate_safe_prime_with_rng(rng, Some(P::PRIME_BITS));
        let q = P::SingleUint::generate_safe_prime_with_rng(rng, Some(P::PRIME_BITS));

        Self { p, q }
    }

    /// Euler's totient function of `p * q` - the number of positive integers up to `p * q`
    /// that are relatively prime to it.
    /// Since `p` and `q` are primes, returns `(p - 1) * (q - 1)`.
    pub fn totient(&self) -> NonZero<P::DoubleUint> {
        let one = P::SingleUint::ONE;
        let p_minus_one = self.p.checked_sub(&one).unwrap();
        let q_minus_one = self.q.checked_sub(&one).unwrap();
        NonZero::new(p_minus_one.mul_wide(&q_minus_one)).unwrap()
    }

    pub fn public_key(&self) -> PublicKeyPaillier<P> {
        PublicKeyPaillier {
            modulus: self.p.mul_wide(&self.q),
        }
    }

    pub fn rns_split(&self, elem: &P::DoubleUint) -> (P::SingleUintMod, P::SingleUintMod) {
        // TODO: the returned values must be zeroized - the moduli are secret
        let p_big: P::DoubleUint = self.p.into_wide();
        let q_big: P::DoubleUint = self.q.into_wide();
        // TODO: speed up potential here since we know p and q are small
        let p_rem_big = *elem % NonZero::new(p_big).unwrap();
        let q_rem_big = *elem % NonZero::new(q_big).unwrap();
        let p_rem = P::SingleUint::try_from_wide(p_rem_big).unwrap();
        let q_rem = P::SingleUint::try_from_wide(q_rem_big).unwrap();

        let p_rem_mod = P::SingleUintMod::new(&p_rem, &NonZero::new(self.p).unwrap());
        let q_rem_mod = P::SingleUintMod::new(&q_rem, &NonZero::new(self.q).unwrap());
        (p_rem_mod, q_rem_mod)
    }

    fn sqrt_part(&self, x: &P::SingleUintMod, modulus: &P::SingleUint) -> Option<P::SingleUintMod> {
        // Both `p` and `q` are safe primes, so they're 3 mod 4.
        // This means that if square root exists, it must be of the form `+/- x^((p+1)/4)`,
        // CHECK: can we get an overflow here?
        let modulus_plus_one = modulus.checked_add(&P::SingleUint::ONE).unwrap();
        let candidate = x.pow(&(modulus_plus_one >> 2));
        if candidate * candidate == *x {
            Some(candidate)
        } else {
            None
        }
    }

    pub fn sqrt(
        &self,
        rns: &(P::SingleUintMod, P::SingleUintMod),
    ) -> Option<(P::SingleUintMod, P::SingleUintMod)> {
        // TODO: when we can extract the modulus from `SingleUintMod`, this can be moved there.
        // For now we have to keep this a method of SecretKey to have access to `p` and `q`.
        let (p_part, q_part) = *rns;
        let p_res = self.sqrt_part(&p_part, &self.p);
        let q_res = self.sqrt_part(&q_part, &self.q);
        match (p_res, q_res) {
            (Some(p), Some(q)) => Some((p, q)),
            _ => None,
        }
    }

    pub fn rns_join(&self, rns: &(P::SingleUintMod, P::SingleUintMod)) -> P::DoubleUint {
        let (p_part, q_part) = *rns;
        let pk = self.public_key();
        let p_big: P::DoubleUint = self.p.into_wide();
        let q_big: P::DoubleUint = self.q.into_wide();
        let pq_big = p_big.checked_add(&q_big).unwrap();
        let pq_m = P::DoubleUintMod::new(&pq_big, &pk.modulus());
        let inv = pq_m.invert().unwrap();

        let p_part_big: P::DoubleUint = p_part.retrieve().into_wide();
        let q_part_big: P::DoubleUint = q_part.retrieve().into_wide();

        let p_big_m = P::DoubleUintMod::new(&p_big, &pk.modulus());
        let q_big_m = P::DoubleUintMod::new(&q_big, &pk.modulus());
        let p_part_m = P::DoubleUintMod::new(&p_part_big, &pk.modulus());
        let q_part_m = P::DoubleUintMod::new(&q_part_big, &pk.modulus());

        (inv * (p_part_m * q_big_m + q_part_m * p_big_m)).retrieve()
    }

    pub fn inv_modulus(&self) -> P::DoubleUint {
        let m_nz = self.totient();
        let m = m_nz.as_ref();
        let k = m.trailing_zeros();
        let m_odd = *m >> k;
        let x = self.public_key().modulus();

        let a = x.as_ref().inv_odd_mod(&m_odd).unwrap();
        let b = x.as_ref().inv_mod2k(k);

        // Restore from RNS:
        // x = a mod m_odd = b mod 2^k
        // => x = a + m_odd * ((b - a) * m_odd^(-1) mod 2^k)
        let m_odd_inv = m_odd.inv_mod2k(k);

        // This part is mod 2^k
        let mask = (P::DoubleUint::ONE << k)
            .checked_sub(&P::DoubleUint::ONE)
            .unwrap();
        let t = (b.wrapping_sub(&a).wrapping_mul(&m_odd_inv)) & mask;
        a.checked_add(&m_odd.checked_mul(&t).unwrap()).unwrap()
    }

    pub fn random_field_elem(&self, rng: &mut (impl RngCore + CryptoRng)) -> P::DoubleUint {
        P::DoubleUint::random_mod(rng, &self.totient())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyPaillier<P: PaillierParams> {
    /// N
    modulus: P::DoubleUint,
}

impl<P: PaillierParams> PublicKeyPaillier<P> {
    pub fn modulus_raw(&self) -> P::DoubleUint {
        self.modulus
    }

    pub fn modulus(&self) -> NonZero<P::DoubleUint> {
        // TODO: or just store it as NonZero to begin with?
        NonZero::new(self.modulus).unwrap()
    }

    pub fn random_group_elem_raw(&self, rng: &mut (impl RngCore + CryptoRng)) -> P::DoubleUint {
        P::DoubleUint::random_mod(rng, &self.modulus())
    }

    pub fn random_group_elem(&self, rng: &mut (impl RngCore + CryptoRng)) -> P::DoubleUintMod {
        let r = P::DoubleUint::random_mod(rng, &self.modulus());
        P::DoubleUintMod::new(&r, &self.modulus())
    }

    pub fn random_invertible_group_elem(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> P::DoubleUintMod {
        // TODO: is there a faster way? How many loops on average does it take?
        loop {
            let r = P::DoubleUint::random_mod(rng, &NonZero::new(self.modulus).unwrap());
            let r_m = P::DoubleUintMod::new(&r, &self.modulus());
            if r_m.invert().is_some().into() {
                return r_m;
            }
        }
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
