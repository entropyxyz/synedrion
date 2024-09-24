use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use super::params::PaillierParams;
use crate::uint::{
    subtle::{Choice, ConditionallySelectable},
    Bounded, CheckedAdd, CheckedSub, HasWide, Integer, Invert, NonZero, PowBoundedExp, RandomMod,
    RandomPrimeWithRng, Retrieve, Signed, ToMontgomery,
};
use crypto_bigint::{
    Bounded as TraitBounded, InvMod, Monty, Odd, ShrVartime, Square, WrappingAdd, WrappingSub,
};

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct SecretKeyPaillier<P: PaillierParams> {
    p: P::HalfUint,
    q: P::HalfUint,
}

impl<P: PaillierParams> Debug for SecretKeyPaillier<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.write_str("[REDACTED ")?;
        f.write_str(core::any::type_name::<Self>())?;
        f.write_str("]")
    }
}

impl<P: PaillierParams> SecretKeyPaillier<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let p = P::HalfUint::generate_safe_prime_with_rng(
            rng,
            P::PRIME_BITS as u32,
            <P as PaillierParams>::HalfUint::BITS,
        );
        let q = P::HalfUint::generate_safe_prime_with_rng(
            rng,
            P::PRIME_BITS as u32,
            <P as PaillierParams>::HalfUint::BITS,
        );

        Self { p, q }
    }

    pub fn to_precomputed(&self) -> SecretKeyPaillierPrecomputed<P> {
        // Euler's totient function of $p q$ - the number of positive integers up to $p q$
        // that are relatively prime to it.
        // Since $p$ and $q$ are primes, $\phi(p q) = (p - 1) (q - 1)$.
        let one = <P::HalfUint as Integer>::one();
        let p_minus_one = self
            .p
            .checked_sub(&one)
            .expect("`p` is prime, so greater than one");
        let q_minus_one = self
            .q
            .checked_sub(&one)
            .expect("`q` is prime, so greater than one");
        let totient = Bounded::new(p_minus_one.mul_wide(&q_minus_one), P::MODULUS_BITS as u32)
            .expect("The pre-configured bound set in `P::MODULUS_BITS` is assumed to be valid");

        let precomputed_mod_p = P::HalfUintMod::new_params_vartime(
            Odd::new(self.p.clone()).expect("`p` is assumed to be a prime greater than 2"),
        );
        let precomputed_mod_q = P::HalfUintMod::new_params_vartime(
            Odd::new(self.q.clone()).expect("`q` is assumed to be a prime greater than 2"),
        );

        let public_key = PublicKeyPaillier {
            modulus: self.p.mul_wide(&self.q),
        };
        let public_key = public_key.to_precomputed();

        let inv_totient = totient
            .into_inner()
            .to_montgomery(public_key.precomputed_modulus())
            .invert()
            .expect("The modulus is pq. ϕ(pq) = (p-1)(q-1) is invertible mod pq because neither (p-1) nor (q-1) share factors with pq.");

        let modulus: &P::Uint = public_key.modulus(); // pq
        let inv_modulus = Bounded::new(
            modulus
                .inv_mod(totient.as_ref())
                .expect("pq is invertible mod ϕ(pq) because gcd(pq, (p-1)(q-1)) = 1"),
            P::MODULUS_BITS as u32,
        )
        .expect("We assume `P::MODULUS_BITS` is properly configured");

        let inv_p_mod_q = self
            .p
            .clone()
            .to_montgomery(&precomputed_mod_q)
            .invert()
            .expect("All non-zero integers mod a prime have a multiplicative inverse");

        let inv_q_mod_p = self
            .q
            .clone()
            .to_montgomery(&precomputed_mod_p)
            .invert()
            .expect("All non-zero integers have a multiplicative inverse mod a prime");

        // Calculate $u$ such that $u = 1 \mod p$ and $u = -1 \mod q$.
        // Using step of Garner's algorithm:
        // $u = q - 1 + q (2 q^{-1} - 1 \mod p)$
        let t = (inv_q_mod_p.clone() + inv_q_mod_p.clone()
            - <P::HalfUintMod as Monty>::one(precomputed_mod_p.clone()))
        .retrieve();
        // Note that the wrapping add/sub won't overflow by construction.
        let nonsquare_sampling_constant = t
            .mul_wide(&self.q)
            .wrapping_add(&self.q.clone().into_wide())
            .wrapping_sub(&<P::Uint as Integer>::one());

        let nonsquare_sampling_constant = P::UintMod::new(
            nonsquare_sampling_constant,
            Clone::clone(public_key.precomputed_modulus()),
        );

        SecretKeyPaillierPrecomputed {
            sk: self.clone(),
            totient,
            inv_totient,
            inv_modulus,
            inv_p_mod_q,
            nonsquare_sampling_constant,
            precomputed_mod_p: precomputed_mod_p.clone(),
            precomputed_mod_q: precomputed_mod_q.clone(),
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
    precomputed_mod_p: <P::HalfUintMod as Monty>::Params,
    precomputed_mod_q: <P::HalfUintMod as Monty>::Params,
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
            Signed::new_positive(self.sk.p.clone().into_wide(), P::PRIME_BITS as u32).unwrap(),
            Signed::new_positive(self.sk.q.clone().into_wide(), P::PRIME_BITS as u32).unwrap(),
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

    fn precomputed_mod_p(&self) -> &<P::HalfUintMod as Monty>::Params {
        &self.precomputed_mod_p
    }

    fn precomputed_mod_q(&self) -> &<P::HalfUintMod as Monty>::Params {
        &self.precomputed_mod_q
    }

    pub fn public_key(&self) -> &PublicKeyPaillierPrecomputed<P> {
        &self.public_key
    }

    pub fn rns_split(&self, elem: &P::Uint) -> (P::HalfUintMod, P::HalfUintMod) {
        // TODO (#77): zeroize intermediate values

        // May be some speed up potential here since we know p and q are small,
        // but it needs to be supported by `crypto-bigint`.
        let p_rem = *elem % NonZero::new(self.sk.p.clone().into_wide()).unwrap();
        let q_rem = *elem % NonZero::new(self.sk.q.clone().into_wide()).unwrap();
        let p_rem_half = P::HalfUint::try_from_wide(p_rem).unwrap();
        let q_rem_half = P::HalfUint::try_from_wide(q_rem).unwrap();

        let p_rem_mod = P::HalfUintMod::new(p_rem_half, self.precomputed_mod_p().clone());
        let q_rem_mod = P::HalfUintMod::new(q_rem_half, self.precomputed_mod_q().clone());
        (p_rem_mod, q_rem_mod)
    }

    fn sqrt_part(&self, x: &P::HalfUintMod, modulus: &P::HalfUint) -> Option<P::HalfUintMod> {
        // Both `p` and `q` are safe primes, so they're 3 mod 4.
        // This means that if square root exists, it must be of the form `+/- x^((modulus+1)/4)`.
        // Also it means that `(modulus+1)/4 == modulus/4+1`
        // (this will help avoid a possible overflow).
        let candidate = x.pow_bounded_exp(
            &modulus
                .wrapping_shr_vartime(2)
                .wrapping_add(&<P::HalfUint as Integer>::one()),
            P::PRIME_BITS as u32 - 1,
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
        let (p_part, q_part) = rns;
        let p_res = self.sqrt_part(p_part, &self.sk.p);
        let q_res = self.sqrt_part(q_part, &self.sk.q);
        match (p_res, q_res) {
            (Some(p), Some(q)) => Some((p, q)),
            _ => None,
        }
    }

    pub fn rns_join(&self, rns: &(P::HalfUintMod, P::HalfUintMod)) -> P::Uint {
        // We have `a = x mod p`, `b = x mod q`; we want to find `x mod (pq)`.
        // One step of Garner's algorithm:
        // x = a + p * ((b - a) * p^{-1} mod q)

        let (a_mod_p, b_mod_q) = rns;

        let a_half = a_mod_p.retrieve();
        let a_mod_q = P::HalfUintMod::new(a_half.clone(), self.precomputed_mod_q.clone());
        let x = ((b_mod_q.clone() - a_mod_q) * self.inv_p_mod_q.clone()).retrieve();
        let a = a_half.into_wide();

        // Will not overflow since 0 <= x < q, and 0 <= a < p.
        a.checked_add(&self.sk.p.mul_wide(&x))
            .expect("Will not overflow since 0 <= x < q, and 0 <= a < p.")
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
        let odd = Odd::new(self.modulus).expect("Assumed to  be odd");
        let precomputed_modulus = P::UintMod::new_params_vartime(odd);
        let precomputed_modulus_squared = P::WideUintMod::new_params_vartime(
            Odd::new(self.modulus.square_wide()).expect("Square of odd number is odd"),
        );

        PublicKeyPaillierPrecomputed {
            pk: self.clone(),
            precomputed_modulus,
            precomputed_modulus_squared,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PublicKeyPaillierPrecomputed<P: PaillierParams> {
    pk: PublicKeyPaillier<P>,
    precomputed_modulus: <P::UintMod as Monty>::Params,
    precomputed_modulus_squared: <P::WideUintMod as Monty>::Params,
}

impl<P: PaillierParams> PublicKeyPaillierPrecomputed<P> {
    pub fn as_minimal(&self) -> &PublicKeyPaillier<P> {
        &self.pk
    }

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
    pub fn precomputed_modulus(&self) -> &<P::UintMod as Monty>::Params {
        &self.precomputed_modulus
    }

    /// Returns precomputed parameters for integers modulo N^2
    pub fn precomputed_modulus_squared(&self) -> &<P::WideUintMod as Monty>::Params {
        &self.precomputed_modulus_squared
    }

    /// Finds an invertible group element via rejection sampling. Returns the
    /// element in Montgomery form.
    pub fn random_invertible_group_elem(&self, rng: &mut impl CryptoRngCore) -> P::UintMod {
        let modulus = self.modulus_nonzero();
        loop {
            let r = P::Uint::random_mod(rng, &modulus);
            let r_m = P::UintMod::new(r, self.precomputed_modulus().clone());
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
