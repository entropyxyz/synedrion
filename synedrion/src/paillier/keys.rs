use alloc::boxed::Box;
use core::fmt::Debug;

use crypto_bigint::{InvMod, Monty, Odd, ShrVartime, Square, WrappingAdd, WrappingSub};
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::params::PaillierParams;
use crate::uint::{
    subtle::{Choice, ConditionallySelectable},
    Bounded, CheckedAdd, CheckedSub, HasWide, Integer, Invert, NonZero, PowBoundedExp, RandomMod, RandomPrimeWithRng,
    Retrieve, Signed, ToMontgomery,
};

#[derive(Debug, Deserialize)]
pub(crate) struct SecretKeyPaillier<P: PaillierParams> {
    p: SecretBox<P::HalfUint>,
    q: SecretBox<P::HalfUint>,
}

impl<P: PaillierParams> PartialEq for SecretKeyPaillier<P> {
    fn eq(&self, other: &Self) -> bool {
        self.p.expose_secret() == other.p.expose_secret() && self.q.expose_secret() == other.q.expose_secret()
    }
}

impl<P: PaillierParams> Clone for SecretKeyPaillier<P> {
    fn clone(&self) -> Self {
        Self {
            p: Box::new(self.p.expose_secret().clone()).into(),
            q: Box::new(self.q.expose_secret().clone()).into(),
        }
    }
}

impl<P: PaillierParams> Serialize for SecretKeyPaillier<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (self.p.expose_secret(), self.q.expose_secret()).serialize(serializer)
    }
}

impl<P: PaillierParams> SecretKeyPaillier<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let p = P::HalfUint::generate_safe_prime_with_rng(rng, P::PRIME_BITS as u32);
        let q = P::HalfUint::generate_safe_prime_with_rng(rng, P::PRIME_BITS as u32);

        Self {
            p: Box::new(p).into(),
            q: Box::new(q).into(),
        }
    }

    pub fn to_precomputed(&self) -> SecretKeyPaillierPrecomputed<P> {
        // Euler's totient function of $p q$ - the number of positive integers up to $p q$
        // that are relatively prime to it.
        // Since $p$ and $q$ are primes, $\phi(p q) = (p - 1) (q - 1)$.
        let one = <P::HalfUint as Integer>::one();
        let p_minus_one = self
            .p
            .expose_secret()
            .checked_sub(&one)
            .expect("`p` is prime, so greater than one");
        let q_minus_one = self
            .q
            .expose_secret()
            .checked_sub(&one)
            .expect("`q` is prime, so greater than one");
        let totient = Bounded::new(p_minus_one.mul_wide(&q_minus_one), P::MODULUS_BITS as u32)
            .expect("The pre-configured bound set in `P::MODULUS_BITS` is assumed to be valid");

        let precomputed_mod_p = P::HalfUintMod::new_params_vartime(
            Odd::new(self.p.expose_secret().clone()).expect("`p` is assumed to be a prime greater than 2"),
        );
        let precomputed_mod_q = P::HalfUintMod::new_params_vartime(
            Odd::new(self.q.expose_secret().clone()).expect("`q` is assumed to be a prime greater than 2"),
        );

        let public_key = PublicKeyPaillier {
            modulus: self.p.expose_secret().mul_wide(self.q.expose_secret()),
        };
        let public_key = public_key.to_precomputed();

        let inv_totient = totient
            .into_inner()
            .to_montgomery(public_key.precomputed_modulus())
            .invert()
            .expect(concat![
                "The modulus is pq. ϕ(pq) = (p-1)(q-1) is invertible mod pq because ",
                "neither (p-1) nor (q-1) share factors with pq."
            ]);

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
            .expose_secret()
            .clone()
            .to_montgomery(&precomputed_mod_q)
            .invert()
            .expect("All non-zero integers mod a prime have a multiplicative inverse");

        let inv_q_mod_p = self
            .q
            .expose_secret()
            .clone()
            .to_montgomery(&precomputed_mod_p)
            .invert()
            .expect("All non-zero integers have a multiplicative inverse mod a prime");

        // Calculate $u$ such that $u = 1 \mod p$ and $u = -1 \mod q$.
        // Using step of Garner's algorithm:
        // $u = q - 1 + q (2 q^{-1} - 1 \mod p)$
        let t = (inv_q_mod_p.clone() + inv_q_mod_p.clone() - <P::HalfUintMod as Monty>::one(precomputed_mod_p.clone()))
            .retrieve();
        // Note that the wrapping add/sub won't overflow by construction.
        let nonsquare_sampling_constant = t
            .mul_wide(self.q.expose_secret())
            .wrapping_add(&self.q.expose_secret().clone().into_wide())
            .wrapping_sub(&<P::Uint as Integer>::one());

        let nonsquare_sampling_constant = P::UintMod::new(
            nonsquare_sampling_constant,
            Clone::clone(public_key.precomputed_modulus()),
        );

        SecretKeyPaillierPrecomputed {
            sk: self.clone(),
            totient: Box::new(totient).into(),
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

#[derive(Debug, Clone)]
pub(crate) struct SecretKeyPaillierPrecomputed<P: PaillierParams> {
    sk: SecretKeyPaillier<P>,
    totient: SecretBox<Bounded<P::Uint>>,
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

impl<P> SecretKeyPaillierPrecomputed<P>
where
    P: PaillierParams,
{
    pub fn to_minimal(&self) -> SecretKeyPaillier<P> {
        self.sk.clone()
    }

    #[allow(clippy::type_complexity)]
    pub fn primes(&self) -> (SecretBox<Signed<P::Uint>>, SecretBox<Signed<P::Uint>>) {
        // The primes are positive, but where this method is used Signed is needed,
        // so we return that for convenience.
        (
            SecretBox::new(Box::new(
                Signed::new_positive(self.sk.p.expose_secret().clone().into_wide(), P::PRIME_BITS as u32).expect(
                    concat![
                        "The prime p in the `SecretKeyPaillier` are 'safe primes' ",
                        "and positive by construction; the bound is assumed to be configured correctly by the user."
                    ],
                ),
            )),
            SecretBox::new(Box::new(
                Signed::new_positive(self.sk.q.expose_secret().clone().into_wide(), P::PRIME_BITS as u32).expect(
                    concat![
                        "The prime q in the `SecretKeyPaillier` are 'safe primes' ",
                        "and positive by construction; the bound is assumed to be configured correctly by the user."
                    ],
                ),
            )),
        )
    }

    /// Returns Euler's totient function (`φ(n)`) of the modulus, wrapped in a [`SecretBox`].
    pub fn totient(&self) -> SecretBox<Bounded<P::Uint>> {
        self.totient.clone()
    }

    /// Returns Euler's totient function (`φ(n)`) of the modulus as a [`NonZero`], wrapped in a [`SecretBox`].
    pub fn totient_nonzero(&self) -> SecretBox<NonZero<P::Uint>> {
        let p = NonZero::new(self.totient.expose_secret().into_inner()).expect(concat![
            "φ(n) is never zero for n >= 1; n is strictly greater than 1 ",
            "because it is (p-1)(q-1) and given that both p and q are prime ",
            "they are both strictly greater than 1"
        ]);
        Box::new(p).into()
    }

    /// Returns $\phi(N)^{-1} \mod N$
    pub fn inv_totient(&self) -> SecretBox<P::UintMod> {
        Box::new(self.inv_totient).into()
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
        // May be some speed up potential here since we know p and q are small,
        // but it needs to be supported by `crypto-bigint`.
        let mut p_rem = *elem % NonZero::new(self.sk.p.expose_secret().clone().into_wide()).expect("`p` is non-zero");
        let mut q_rem = *elem % NonZero::new(self.sk.q.expose_secret().clone().into_wide()).expect("`q` is non-zero");
        let p_rem_half = P::HalfUint::try_from_wide(p_rem).expect("`p` fits into `HalfUint`");
        let q_rem_half = P::HalfUint::try_from_wide(q_rem).expect("`q` fits into `HalfUint`");

        let p_rem_mod = p_rem_half.to_montgomery(self.precomputed_mod_p());
        let q_rem_mod = q_rem_half.to_montgomery(self.precomputed_mod_q());

        // crypto_bigint::Uint<LIMB> does not impl `ZeroizeOnDrop` (only
        // `DefaultIsZeroes`) so we're stuck with this rather clunky way of zeroizing.
        p_rem.zeroize();
        q_rem.zeroize();

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

    pub fn sqrt(&self, rns: &(P::HalfUintMod, P::HalfUintMod)) -> Option<(P::HalfUintMod, P::HalfUintMod)> {
        // TODO (#73): when we can extract the modulus from `HalfUintMod`, this can be moved there.
        // For now we have to keep this a method of SecretKey to have access to `p` and `q`.
        let (p_part, q_part) = rns;
        let p_res = self.sqrt_part(p_part, self.sk.p.expose_secret());
        let q_res = self.sqrt_part(q_part, self.sk.q.expose_secret());
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
        a.checked_add(&self.sk.p.expose_secret().mul_wide(&x))
            .expect("Will not overflow since 0 <= x < q, and 0 <= a < p.")
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
        Bounded::new(*self.pk.modulus(), P::MODULUS_BITS as u32).expect("the modulus can be bounded by 2^MODULUS_BITS")
    }

    pub fn modulus_nonzero(&self) -> NonZero<P::Uint> {
        NonZero::new(*self.modulus()).expect("the modulus is non-zero")
    }

    pub fn modulus_wide_nonzero(&self) -> NonZero<P::WideUint> {
        NonZero::new(self.pk.modulus().into_wide()).expect("the modulus is non-zero")
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
pub fn make_broken_paillier_key<P>(rng: &mut impl CryptoRngCore, p: u64) -> SecretKeyPaillier<P>
where
    P: PaillierParams,
{
    use secrecy::SecretBox;

    let p = P::HalfUint::from(p);
    let q = P::HalfUint::generate_safe_prime_with_rng(rng, P::PRIME_BITS as u32);
    SecretKeyPaillier {
        p: SecretBox::new(Box::new(p)),
        q: SecretBox::new(Box::new(q)),
    }
}
#[cfg(test)]
mod tests {
    use super::SecretKeyPaillier;
    use crate::cggmp21::{PaillierProduction, PaillierTest2};
    use crate::paillier::params::PaillierTest;
    use crate::paillier::{CiphertextMod, PaillierParams};

    use rand::SeedableRng;
    use rand_core::OsRng;
    use serde::Serialize;
    use serde_assert::Token;

    #[test]
    fn basics() {
        let sk = SecretKeyPaillier::<PaillierTest2>::random(&mut OsRng).to_precomputed();
        let _pk = sk.public_key();
    }

    #[test]
    fn debug_redacts_secrets() {
        let sk = SecretKeyPaillier::<PaillierTest2>::random(&mut OsRng);

        let debug_output = format!("Sikrit {:?}", sk);
        assert_eq!(
            debug_output,
            concat![
                "Sikrit SecretKeyPaillier ",
                "{ p: SecretBox<crypto_bigint::uint::Uint<8>>([REDACTED]), ",
                "q: SecretBox<crypto_bigint::uint::Uint<8>>([REDACTED]) }"
            ]
        );
    }

    #[test]
    fn serialization_and_clone_works() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123456);
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut rng);

        let serializer = serde_assert::Serializer::builder().build();
        let sk_ser = sk.serialize(&serializer).unwrap();
        let expected_tokens = [
            Token::Tuple { len: 2 },
            Token::Str(
                concat![
                    "d30b226b6f3a29a048826fa4cf85f83a7aa03d097ec89aea7b1f35633f5719e1",
                    "80b93af2508fc289c196078937d9d8a61af6d7768301d231bafdf87c10f28f8a"
                ]
                .into(),
            ),
            Token::Str(
                concat![
                    "7f0e0796291488cf87ed167109d9daf34e4ad5cc1399c9d034803b9536525989",
                    "63abf19b9675653a51e619651f1ab15e66256829c250903fae3ab96683b5aff9"
                ]
                .into(),
            ),
            Token::TupleEnd,
        ];
        assert_eq!(sk_ser, expected_tokens);

        // Clone works
        let clone = sk.clone();
        assert_eq!(sk, clone);
    }

    #[test_log::test]
    fn malicious_paillier_key() {
        type Uint = <PaillierProduction as PaillierParams>::Uint;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123456);
        let sk = super::make_broken_paillier_key::<PaillierProduction>(&mut rng, 23);
        let sikrit = {
            let s = "attack at dawn!".as_bytes();
            let mut buf = [0u8; Uint::BYTES];
            buf[Uint::BYTES - s.len()..].copy_from_slice(s);
            buf
        };

        let sikrit_uint = Uint::from_be_slice(&sikrit);
        let sk_precomp = sk.to_precomputed();
        let ciphertext = CiphertextMod::new(&mut rng, sk_precomp.public_key(), &sikrit_uint);

        let decrypted = ciphertext.decrypt(&sk_precomp);
        assert_eq!(decrypted, sikrit_uint);
    }
}
