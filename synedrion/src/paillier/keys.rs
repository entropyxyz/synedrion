use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::params::PaillierParams;
use crate::tools::hashing::{Chain, Hashable};
use crate::uint::{
    subtle::{Choice, ConditionallySelectable},
    Bounded, CheckedAdd, CheckedSub, HasWide, Integer, Invert, NonZero, PowBoundedExp, RandomMod,
    RandomPrimeWithRng, Retrieve, Signed, UintLike, UintModLike,
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
        let totient =
            Bounded::new(p_minus_one.mul_wide(&q_minus_one), P::MODULUS_BITS as u32).unwrap();

        let precomputed_mod_p = P::HalfUintMod::new_precomputed(&NonZero::new(self.p).unwrap());
        let precomputed_mod_q = P::HalfUintMod::new_precomputed(&NonZero::new(self.q).unwrap());

        let public_key = PublicKeyPaillier {
            modulus: self.p.mul_wide(&self.q),
        };
        let public_key = public_key.to_precomputed();

        let inv_totient = totient
            .as_ref()
            .to_mod(public_key.precomputed_modulus())
            .invert()
            .unwrap();

        let modulus: &P::Uint = public_key.modulus();
        let inv_modulus = Bounded::new(
            modulus.inv_mod(totient.as_ref()).unwrap(),
            P::MODULUS_BITS as u32,
        )
        .unwrap();

        let inv_p_mod_q = self.p.to_mod(&precomputed_mod_q).invert().unwrap();
        let inv_q_mod_p = self.q.to_mod(&precomputed_mod_p).invert().unwrap();

        // Calculate $u$ such that $u = 1 \mod p$ and $u = -1 \mod q$.
        // Using step of Garner's algorithm:
        // $u = q - 1 + q (2 q^{-1} - 1 \mod p)$
        let t = (inv_q_mod_p + inv_q_mod_p - P::HalfUintMod::one(&precomputed_mod_p)).retrieve();
        // Note that the wrapping add/sub won't overflow by construction.
        let nonsquare_sampling_constant = t
            .mul_wide(&self.q)
            .wrapping_add(&self.q.into_wide())
            .wrapping_sub(&P::Uint::ONE);
        let nonsquare_sampling_constant = P::UintMod::new(
            &nonsquare_sampling_constant,
            &public_key.precomputed_modulus,
        );

        SecretKeyPaillierPrecomputed {
            sk: self.clone(),
            totient,
            inv_totient,
            inv_modulus,
            inv_p_mod_q,
            nonsquare_sampling_constant,
            precomputed_mod_p,
            precomputed_mod_q,
            public_key,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SecretKeyPaillierPrecomputed<P: PaillierParams> {
    sk: SecretKeyPaillier<P>,
    totient: Bounded<P::Uint>,
    /// $\phi(N)^{-1} \mod N$
    inv_totient: P::UintMod,
    /// $N^{-1} \mod \phi(N)$
    inv_modulus: Bounded<P::Uint>,
    inv_p_mod_q: P::HalfUintMod,
    // $u$ such that $u = 1 \mod p$ and $u = -1 \mod q$.
    nonsquare_sampling_constant: P::UintMod,
    precomputed_mod_p: <P::HalfUintMod as UintModLike>::Precomputed,
    precomputed_mod_q: <P::HalfUintMod as UintModLike>::Precomputed,
    public_key: PublicKeyPaillierPrecomputed<P>,
}

impl<P: PaillierParams> SecretKeyPaillierPrecomputed<P> {
    pub fn to_minimal(&self) -> SecretKeyPaillier<P> {
        self.sk.clone()
    }

    pub fn primes(&self) -> (Signed<P::Uint>, Signed<P::Uint>) {
        // The primes are positive, but where this method is used Signed is needed,
        // so we return that for convenience.
        // TODO (#77): must be wrapped in a Secret
        (
            Signed::new_positive(self.sk.p.into_wide(), P::PRIME_BITS as u32).unwrap(),
            Signed::new_positive(self.sk.q.into_wide(), P::PRIME_BITS as u32).unwrap(),
        )
    }

    pub fn totient(&self) -> &Bounded<P::Uint> {
        // TODO (#77): must be wrapped in a Secret
        &self.totient
    }

    /// Returns Euler's totient function of the modulus.
    pub fn totient_nonzero(&self) -> NonZero<P::Uint> {
        // TODO (#77): must be wrapped in a Secret
        NonZero::new(*self.totient.as_ref()).unwrap()
    }

    /// Returns $\phi(N)^{-1} \mod N$
    pub fn inv_totient(&self) -> &P::UintMod {
        // TODO (#77): must be wrapped in a Secret
        &self.inv_totient
    }

    /// Returns $N^{-1} \mod \phi(N)$
    pub fn inv_modulus(&self) -> &Bounded<P::Uint> {
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
        // TODO (#77): zeroize intermediate values

        // May be some speed up potential here since we know p and q are small,
        // but it needs to be supported by `crypto-bigint`.
        let p_rem = *elem % NonZero::new(self.sk.p.into_wide()).unwrap();
        let q_rem = *elem % NonZero::new(self.sk.q.into_wide()).unwrap();
        let p_rem_half = P::HalfUint::try_from_wide(p_rem).unwrap();
        let q_rem_half = P::HalfUint::try_from_wide(q_rem).unwrap();

        let p_rem_mod = p_rem_half.to_mod(self.precomputed_mod_p());
        let q_rem_mod = q_rem_half.to_mod(self.precomputed_mod_q());
        (p_rem_mod, q_rem_mod)
    }

    fn sqrt_part(&self, x: &P::HalfUintMod, modulus: &P::HalfUint) -> Option<P::HalfUintMod> {
        // Both `p` and `q` are safe primes, so they're 3 mod 4.
        // This means that if square root exists, it must be of the form `+/- x^((modulus+1)/4)`.
        // Also it means that `(modulus+1)/4 == modulus/4+1`
        // (this will help avoid a possible overflow).
        let candidate = x.pow_bounded_exp(
            &modulus.shr_vartime(2).wrapping_add(&P::HalfUint::ONE),
            P::PRIME_BITS - 1,
        );
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
        // TODO (#73): when we can extract the modulus from `HalfUintMod`, this can be moved there.
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
        // We have `a = x mod p`, `b = x mod q`; we want to find `x mod (pq)`.
        // One step of Garner's algorithm:
        // x = a + p * ((b - a) * p^{-1} mod q)

        let (a_mod_p, b_mod_q) = *rns;

        let a_half = a_mod_p.retrieve();
        let a_mod_q = a_half.to_mod(&self.precomputed_mod_q);
        let x = ((b_mod_q - a_mod_q) * self.inv_p_mod_q).retrieve();
        let a = a_half.into_wide();

        // Will not overflow since 0 <= x < q, and 0 <= a < p.
        a.checked_add(&self.sk.p.mul_wide(&x)).unwrap()
    }

    pub fn random_field_elem(&self, rng: &mut impl CryptoRngCore) -> Bounded<P::Uint> {
        Bounded::new(
            P::Uint::random_mod(rng, &self.totient_nonzero()),
            P::MODULUS_BITS as u32,
        )
        .unwrap()
    }

    /// Returns a random $w \in [0, N)$ such that $w$ is not a square modulo $N$,
    /// where $N$ is the public key
    /// (or, equivalently, such that the Jacobi symbol $(w|N) = -1$).
    pub fn random_nonsquare(&self, rng: &mut impl CryptoRngCore) -> P::Uint {
        /*
        (The sampling method and the explanation by Thomas Pornin)

        Recall that `nonsquare_sampling_constant` $u$ is such that
        $u = 1 \mod p$ and $u = -1 \mod q$, so $u^2 = 1 \mod N$.

        For an $x \in \mathbb{Z}_N^*$ (that is, an invertible element),
        consider the set $S_x = {x, -x, u x, -u x}$.
        For any $x$ and $x^\prime$, then either $S_x = S_{x^\prime}$, or $S_x$ and $S_{x^\prime}$
        are completely disjoint: the sets $S_x$ make a partition of $\mathbb{Z}_N^*$.

        Moreover, exactly two of the four elements of $S_x$ is a square modulo $N$.
        If $x$ is the square in $S_x$, then the Jacobi symbols $(x|N)$ and $(-x|N)$
        are both equal to 1, while the Jacobi symbols $(u x|N)$ and $(-u x|N)$
        are both equal to -1.

        In order to get a uniform integer of Jacobi symbol -1,
        we need to make a uniform selection of $S_x$,
        which we get by selecting $y$ uniformly from $\mathbb{Z}_N^*$ and taking $x = y^2 \mod N$.
        After that, we select uniformly between $u x$ and $-u x$.
        */
        let y = self.public_key.random_invertible_group_elem(rng);
        let b = Choice::from(rng.next_u32() as u8 & 1);
        let w = self.nonsquare_sampling_constant * y.square();
        P::UintMod::conditional_select(&w, &-w, b).retrieve()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublicKeyPaillier<P: PaillierParams> {
    modulus: P::Uint, // TODO (#104): wrap it in `crypto_bigint::Odd`
}

impl<P: PaillierParams> PublicKeyPaillier<P> {
    pub fn modulus(&self) -> &P::Uint {
        &self.modulus
    }

    pub fn to_precomputed(&self) -> PublicKeyPaillierPrecomputed<P> {
        // Note that this ensures that `self.modulus` is odd,
        // otherwise creating the Montgomery parameters fails.
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

#[derive(Debug, Clone, Copy)]
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

    pub fn modulus_bounded(&self) -> Bounded<P::Uint> {
        Bounded::new(*self.pk.modulus(), P::MODULUS_BITS as u32).unwrap()
    }

    pub fn modulus_nonzero(&self) -> NonZero<P::Uint> {
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

    pub fn random_invertible_group_elem(&self, rng: &mut impl CryptoRngCore) -> P::UintMod {
        // Finding an invertible element via rejection sampling.
        loop {
            let r = P::Uint::random_mod(rng, &self.modulus_nonzero());
            let r_m = r.to_mod(self.precomputed_modulus());
            if r_m.invert().is_some().into() {
                return r_m;
            }
        }
    }
}

impl<P: PaillierParams> PartialEq for PublicKeyPaillierPrecomputed<P> {
    fn eq(&self, other: &Self) -> bool {
        self.pk.eq(&other.pk)
    }
}

impl<P: PaillierParams> Eq for PublicKeyPaillierPrecomputed<P> {}

impl<P: PaillierParams> Hashable for PublicKeyPaillier<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.modulus)
    }
}

impl<P: PaillierParams> Hashable for PublicKeyPaillierPrecomputed<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.pk)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::super::params::PaillierTest;
    use super::SecretKeyPaillier;

    #[test]
    fn basics() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let _pk = sk.public_key();
    }
}
