use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::params::PaillierParams;
use crate::tools::hashing::{Chain, Hashable};
use crate::uint::{
    CheckedAdd, CheckedSub, HasWide, Integer, Invert, NonZero, PowBoundedExp, RandomMod,
    RandomPrimeWithRng, Retrieve, UintLike, UintModLike,
};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SecretKeyPaillier<P: PaillierParams> {
    p: P::HalfUint,
    q: P::HalfUint,
}

impl<P: PaillierParams> SecretKeyPaillier<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let p = P::HalfUint::generate_safe_prime_with_rng(rng, Some(P::PRIME_BITS));
        let q = P::HalfUint::generate_safe_prime_with_rng(rng, Some(P::PRIME_BITS));

        Self { p, q }
    }

    pub fn to_precomputed(&self) -> SecretKeyPaillierPrecomputed<P> {
        // Euler's totient function of $p q$ - the number of positive integers up to $p q$
        // that are relatively prime to it.
        // Since $p$ and $q$ are primes, $\phi(p q) = (p - 1) (q - 1)$.
        let one = P::HalfUint::ONE;
        let p_minus_one = self.p.checked_sub(&one).unwrap();
        let q_minus_one = self.q.checked_sub(&one).unwrap();
        let totient = p_minus_one.mul_wide(&q_minus_one);

        let precomputed_mod_p = P::HalfUintMod::new_precomputed(&NonZero::new(self.p).unwrap());
        let precomputed_mod_q = P::HalfUintMod::new_precomputed(&NonZero::new(self.q).unwrap());

        let public_key = PublicKeyPaillier {
            modulus: self.p.mul_wide(&self.q),
        };
        let public_key = public_key.to_precomputed();

        let inv_totient = P::UintMod::new(&totient, public_key.precomputed_modulus())
            .invert()
            .unwrap();

        let modulus: &P::Uint = public_key.modulus();
        let inv_modulus = modulus.inv_mod(&totient).unwrap();

        SecretKeyPaillierPrecomputed {
            sk: self.clone(),
            totient,
            inv_totient,
            inv_modulus,
            precomputed_mod_p,
            precomputed_mod_q,
            public_key,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SecretKeyPaillierPrecomputed<P: PaillierParams> {
    sk: SecretKeyPaillier<P>,
    totient: P::Uint,
    /// $\phi(N)^{-1} \mod N$
    inv_totient: P::UintMod,
    /// $N^{-1} \mod \phi(N)$
    inv_modulus: P::Uint,
    precomputed_mod_p: <P::HalfUintMod as UintModLike>::Precomputed,
    precomputed_mod_q: <P::HalfUintMod as UintModLike>::Precomputed,
    public_key: PublicKeyPaillierPrecomputed<P>,
}

impl<P: PaillierParams> SecretKeyPaillierPrecomputed<P> {
    pub fn to_minimal(&self) -> SecretKeyPaillier<P> {
        self.sk.clone()
    }

    pub fn primes(&self) -> (P::Uint, P::Uint) {
        (self.sk.p.into_wide(), self.sk.q.into_wide())
    }

    pub fn totient(&self) -> &P::Uint {
        &self.totient
    }

    /// Returns Euler's totient function of the modulus.
    pub fn totient_nonzero(&self) -> NonZero<P::Uint> {
        NonZero::new(self.totient).unwrap()
    }

    /// Returns $\phi(N)^{-1} \mod N$
    pub fn inv_totient(&self) -> &P::UintMod {
        &self.inv_totient
    }

    /// Returns $N^{-1} \mod \phi(N)$
    pub fn inv_modulus(&self) -> &P::Uint {
        &self.inv_modulus
    }

    fn precomputed_mod_p(&self) -> &<P::HalfUintMod as UintModLike>::Precomputed {
        &self.precomputed_mod_p
    }

    fn precomputed_mod_q(&self) -> &<P::HalfUintMod as UintModLike>::Precomputed {
        &self.precomputed_mod_q
    }

    pub fn public_key(&self) -> &PublicKeyPaillierPrecomputed<P> {
        &self.public_key
    }

    pub fn rns_split(&self, elem: &P::Uint) -> (P::HalfUintMod, P::HalfUintMod) {
        // TODO: the returned values must be zeroized - the moduli are secret
        let (p_big, q_big) = self.primes();

        // TODO: speed up potential here since we know p and q are small
        // TODO: make sure this is constant-time
        let p_rem_big = *elem % NonZero::new(p_big).unwrap();
        let q_rem_big = *elem % NonZero::new(q_big).unwrap();
        let p_rem = P::HalfUint::try_from_wide(p_rem_big).unwrap();
        let q_rem = P::HalfUint::try_from_wide(q_rem_big).unwrap();

        let p_rem_mod = P::HalfUintMod::new(&p_rem, self.precomputed_mod_p());
        let q_rem_mod = P::HalfUintMod::new(&q_rem, self.precomputed_mod_q());
        (p_rem_mod, q_rem_mod)
    }

    fn sqrt_part(&self, x: &P::HalfUintMod, modulus: &P::HalfUint) -> Option<P::HalfUintMod> {
        // Both `p` and `q` are safe primes, so they're 3 mod 4.
        // This means that if square root exists, it must be of the form `+/- x^((p+1)/4)`,
        // CHECK: can we get an overflow here?
        let modulus_plus_one = modulus.checked_add(&P::HalfUint::ONE).unwrap();
        let candidate = x.pow_bounded_exp(&(modulus_plus_one >> 2), P::PRIME_BITS - 1);
        if candidate.square() == *x {
            Some(candidate)
        } else {
            None
        }
    }

    pub fn sqrt(
        &self,
        rns: &(P::HalfUintMod, P::HalfUintMod),
    ) -> Option<(P::HalfUintMod, P::HalfUintMod)> {
        // TODO: when we can extract the modulus from `HalfUintMod`, this can be moved there.
        // For now we have to keep this a method of SecretKey to have access to `p` and `q`.
        let (p_part, q_part) = *rns;
        let p_res = self.sqrt_part(&p_part, &self.sk.p);
        let q_res = self.sqrt_part(&q_part, &self.sk.q);
        match (p_res, q_res) {
            (Some(p), Some(q)) => Some((p, q)),
            _ => None,
        }
    }

    pub fn rns_join(&self, rns: &(P::HalfUintMod, P::HalfUintMod)) -> P::Uint {
        let (p_part, q_part) = *rns;
        let pk = self.public_key();
        let p_big: P::Uint = self.sk.p.into_wide();
        let q_big: P::Uint = self.sk.q.into_wide();
        let pq_big = p_big.checked_add(&q_big).unwrap();
        let pq_m = P::UintMod::new(&pq_big, pk.precomputed_modulus());
        let inv = pq_m.invert().unwrap();

        let p_part_big: P::Uint = p_part.retrieve().into_wide();
        let q_part_big: P::Uint = q_part.retrieve().into_wide();

        let p_big_m = P::UintMod::new(&p_big, pk.precomputed_modulus());
        let q_big_m = P::UintMod::new(&q_big, pk.precomputed_modulus());
        let p_part_m = P::UintMod::new(&p_part_big, pk.precomputed_modulus());
        let q_part_m = P::UintMod::new(&q_part_big, pk.precomputed_modulus());

        (inv * (p_part_m * q_big_m + q_part_m * p_big_m)).retrieve()
    }

    pub fn random_field_elem(&self, rng: &mut impl CryptoRngCore) -> P::Uint {
        P::Uint::random_mod(rng, &self.totient_nonzero())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublicKeyPaillier<P: PaillierParams> {
    modulus: P::Uint, // $N$
}

impl<P: PaillierParams> PublicKeyPaillier<P> {
    pub fn modulus(&self) -> &P::Uint {
        &self.modulus
    }

    pub fn to_precomputed(&self) -> PublicKeyPaillierPrecomputed<P> {
        let precomputed_modulus = P::UintMod::new_precomputed(&NonZero::new(self.modulus).unwrap());
        let precomputed_modulus_squared =
            P::WideUintMod::new_precomputed(&NonZero::new(self.modulus.square_wide()).unwrap());
        PublicKeyPaillierPrecomputed {
            pk: self.clone(),
            precomputed_modulus,
            precomputed_modulus_squared,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicKeyPaillierPrecomputed<P: PaillierParams> {
    pk: PublicKeyPaillier<P>,
    precomputed_modulus: <P::UintMod as UintModLike>::Precomputed,
    precomputed_modulus_squared: <P::WideUintMod as UintModLike>::Precomputed,
}

impl<P: PaillierParams> PublicKeyPaillierPrecomputed<P> {
    pub fn to_minimal(&self) -> PublicKeyPaillier<P> {
        self.pk.clone()
    }

    pub fn modulus(&self) -> &P::Uint {
        self.pk.modulus()
    }

    pub fn modulus_nonzero(&self) -> NonZero<P::Uint> {
        // TODO: or just store it as NonZero to begin with?
        NonZero::new(*self.modulus()).unwrap()
    }

    /// Returns precomputed parameters for integers modulo N
    pub fn precomputed_modulus(&self) -> &<P::UintMod as UintModLike>::Precomputed {
        &self.precomputed_modulus
    }

    /// Returns precomputed parameters for integers modulo N^2
    pub fn precomputed_modulus_squared(&self) -> &<P::WideUintMod as UintModLike>::Precomputed {
        &self.precomputed_modulus_squared
    }

    pub fn random_group_elem_raw(&self, rng: &mut impl CryptoRngCore) -> P::Uint {
        P::Uint::random_mod(rng, &self.modulus_nonzero())
    }

    // TODO: clippy started marking this as unused starting from Rust 1.72
    // It is used in one of the presigning rounds. Is it a bug, or are the presigning rounds
    // somehow not considered publicly visible? Figure it out later.
    #[allow(dead_code)]
    pub fn random_group_elem(&self, rng: &mut impl CryptoRngCore) -> P::UintMod {
        let r = P::Uint::random_mod(rng, &self.modulus_nonzero());
        P::UintMod::new(&r, self.precomputed_modulus())
    }

    pub fn random_invertible_group_elem(&self, rng: &mut impl CryptoRngCore) -> P::UintMod {
        // TODO: is there a faster way? How many loops on average does it take?
        loop {
            let r = P::Uint::random_mod(rng, &self.modulus_nonzero());
            let r_m = P::UintMod::new(&r, self.precomputed_modulus());
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
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let _pk = sk.public_key();
    }
}
