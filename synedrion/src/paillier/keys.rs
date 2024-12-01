use core::{
    fmt::Debug,
    ops::{AddAssign, SubAssign},
};

use crypto_bigint::{InvMod, Monty, Odd, ShrVartime, Square, WrappingAdd};
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use serde::{Deserialize, Serialize};

use super::{
    params::PaillierParams,
    rsa::{PublicModulus, PublicModulusWire, SecretPrimes, SecretPrimesWire},
};
use crate::{
    tools::Secret,
    uint::{
        subtle::{Choice, ConditionallySelectable},
        Bounded, CheckedAdd, CheckedSub, HasWide, Integer, Invert, NonZero, PowBoundedExp, Retrieve, Signed,
        ToMontgomery,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretPrimesWire<P>: Serialize"))]
#[serde(bound(deserialize = "for<'x> SecretPrimesWire<P>: Deserialize<'x>"))]
pub(crate) struct SecretKeyPaillierWire<P: PaillierParams> {
    primes: SecretPrimesWire<P>,
}

impl<P: PaillierParams> SecretKeyPaillierWire<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            primes: SecretPrimesWire::<P>::random_paillier_blum(rng),
        }
    }

    pub fn into_precomputed(self) -> SecretKeyPaillier<P> {
        SecretKeyPaillier::new(self)
    }

    pub fn public_key(&self) -> PublicKeyPaillierWire<P> {
        PublicKeyPaillierWire::new(&self.primes)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SecretKeyPaillier<P: PaillierParams> {
    /// The secret primes with some precomputed constants,
    primes: SecretPrimes<P>,
    /// The inverse of the totient modulo the modulus ($\phi(N)^{-1} \mod N$).
    inv_totient: Secret<P::UintMod>,
    /// The inverse of the modulus modulo the totient ($N^{-1} \mod \phi(N)$).
    inv_modulus: Secret<Bounded<P::Uint>>,
    /// $p^{-1} \mod q$, a constant used when joining an RNS-represented number using Garner's algorithm.
    inv_p_mod_q: Secret<P::HalfUintMod>,
    // $u$ such that $u = -1 \mod p$ and $u = 1 \mod q$. Used for sampling of non-square residues.
    nonsquare_sampling_constant: Secret<P::UintMod>,
    // TODO (#162): these should be secret, but they are not zeroizable.
    // See https://github.com/RustCrypto/crypto-bigint/issues/704
    /// Montgomery parameters for operations modulo $p$.
    monty_params_mod_p: <P::HalfUintMod as Monty>::Params,
    /// Montgomery parameters for operations modulo $q$.
    monty_params_mod_q: <P::HalfUintMod as Monty>::Params,
    /// The precomputed public key
    public_key: PublicKeyPaillier<P>,
}

impl<P> SecretKeyPaillier<P>
where
    P: PaillierParams,
{
    fn new(secret_key: SecretKeyPaillierWire<P>) -> Self {
        let primes = secret_key.primes.into_precomputed();
        let modulus = primes.modulus_wire().into_precomputed();

        let monty_params_mod_p = P::HalfUintMod::new_params_vartime(*primes.p_half_odd().expose_secret());
        let monty_params_mod_q = P::HalfUintMod::new_params_vartime(*primes.q_half_odd().expose_secret());

        let inv_totient = SecretBox::init_with(|| {
            primes
                .totient()
                .expose_secret()
                .to_montgomery(modulus.monty_params_mod_n())
                .invert()
                .expect(concat![
                    "The modulus is pq. ϕ(pq) = (p-1)(q-1) is invertible mod pq because ",
                    "neither (p-1) nor (q-1) share factors with pq."
                ])
        })
        .into();

        let inv_modulus = SecretBox::init_with(|| {
            Bounded::new(
                (*modulus.modulus())
                    .inv_mod(primes.totient().expose_secret())
                    .expect("pq is invertible mod ϕ(pq) because gcd(pq, (p-1)(q-1)) = 1"),
                P::MODULUS_BITS,
            )
            .expect("We assume `P::MODULUS_BITS` is properly configured")
        })
        .into();

        let inv_p_mod_q = Secret::from(SecretBox::init_with(|| {
            primes
                .p_half()
                .expose_secret()
                // NOTE: `monty_params_mod_q` is cloned here and can remain on the stack.
                // See https://github.com/RustCrypto/crypto-bigint/issues/704
                .to_montgomery(&monty_params_mod_q)
                .invert()
                .expect("All non-zero integers mod a prime have a multiplicative inverse")
        }));

        // Calculate $u$ such that $u = -1 \mod p$ and $u = 1 \mod q$.
        // Using one step of Garner's algorithm:
        // $u = p - 1 + p (2 p^{-1} - 1 \mod q)$

        // Calculate $t = 2 p^{-1} - 1 \mod q$

        let one = SecretBox::init_with(|| {
            // NOTE: `monty_params_mod_q` is cloned here and can remain on the stack.
            // See https://github.com/RustCrypto/crypto-bigint/issues/704
            P::HalfUintMod::one(monty_params_mod_q.clone())
        });
        let mut t_mod = inv_p_mod_q.clone();
        t_mod.expose_secret_mut().add_assign(inv_p_mod_q.expose_secret());
        t_mod.expose_secret_mut().sub_assign(one.expose_secret());
        let t = SecretBox::init_with(|| t_mod.expose_secret().retrieve());

        // Calculate $u$
        // I am not entirely sure if it can be used to learn something about `p` and `q`,
        // so just to be on the safe side it lives in the secret key.

        let u = SecretBox::init_with(|| t.expose_secret().mul_wide(primes.p_half().expose_secret()));
        let u = SecretBox::init_with(|| {
            u.expose_secret()
                .checked_add(primes.p().expose_secret())
                .expect("does not overflow by construction")
        });
        let u = SecretBox::init_with(|| {
            u.expose_secret()
                .checked_sub(&<P::Uint as Integer>::one())
                .expect("does not overflow by construction")
        });
        let nonsquare_sampling_constant =
            SecretBox::init_with(|| P::UintMod::new(*u.expose_secret(), modulus.monty_params_mod_n().clone())).into();

        let public_key = PublicKeyPaillier::new(modulus);

        Self {
            primes,
            inv_totient,
            inv_modulus,
            inv_p_mod_q,
            nonsquare_sampling_constant,
            monty_params_mod_p,
            monty_params_mod_q,
            public_key,
        }
    }

    pub fn into_wire(self) -> SecretKeyPaillierWire<P> {
        SecretKeyPaillierWire {
            primes: self.primes.into_wire(),
        }
    }

    pub fn p_signed(&self) -> SecretBox<Signed<P::Uint>> {
        self.primes.p_signed()
    }

    pub fn q_signed(&self) -> SecretBox<Signed<P::Uint>> {
        self.primes.q_signed()
    }

    pub fn p_wide_signed(&self) -> SecretBox<Signed<P::WideUint>> {
        self.primes.p_wide_signed()
    }

    /// Returns Euler's totient function (`φ(n)`) of the modulus, wrapped in a [`SecretBox`].
    pub fn totient_wide_bounded(&self) -> SecretBox<Bounded<P::WideUint>> {
        self.primes.totient_wide_bounded()
    }

    /// Returns $\phi(N)^{-1} \mod N$
    pub fn inv_totient(&self) -> &SecretBox<P::UintMod> {
        &self.inv_totient
    }

    /// Returns $N^{-1} \mod \phi(N)$
    pub fn inv_modulus(&self) -> &SecretBox<Bounded<P::Uint>> {
        &self.inv_modulus
    }

    pub fn public_key(&self) -> &PublicKeyPaillier<P> {
        &self.public_key
    }

    pub fn rns_split(&self, elem: &P::Uint) -> (P::HalfUintMod, P::HalfUintMod) {
        // May be some speed up potential here since we know p and q are small,
        // but it needs to be supported by `crypto-bigint`.
        let p_rem = *elem % self.primes.p_nonzero().expose_secret();
        let q_rem = *elem % self.primes.q_nonzero().expose_secret();
        let p_rem_half = P::HalfUint::try_from_wide(p_rem).expect("`p` fits into `HalfUint`");
        let q_rem_half = P::HalfUint::try_from_wide(q_rem).expect("`q` fits into `HalfUint`");

        // NOTE: `monty_params_mod_q` is cloned here and can remain on the stack.
        // See https://github.com/RustCrypto/crypto-bigint/issues/704
        let p_rem_mod = p_rem_half.to_montgomery(&self.monty_params_mod_p);
        let q_rem_mod = q_rem_half.to_montgomery(&self.monty_params_mod_q);

        (p_rem_mod, q_rem_mod)
    }

    fn sqrt_part(&self, x: &P::HalfUintMod, modulus: &SecretBox<P::HalfUint>) -> Option<P::HalfUintMod> {
        // Both `p` and `q` are safe primes, so they're 3 mod 4.
        // This means that if square root exists, it must be of the form `+/- x^((modulus+1)/4)`.
        // Also it means that `(modulus+1)/4 == modulus/4+1`
        // (this will help avoid a possible overflow).
        let power = SecretBox::init_with(|| {
            modulus
                .expose_secret()
                .wrapping_shr_vartime(2)
                .wrapping_add(&<P::HalfUint as Integer>::one())
        });
        let candidate = x.pow_bounded_exp(power.expose_secret(), P::PRIME_BITS - 1);
        if candidate.square() == *x {
            Some(candidate)
        } else {
            None
        }
    }

    pub fn rns_sqrt(&self, rns: &(P::HalfUintMod, P::HalfUintMod)) -> Option<(P::HalfUintMod, P::HalfUintMod)> {
        // TODO (#73): when we can extract the modulus from `HalfUintMod`, this can be moved there.
        // For now we have to keep this a method of SecretKey to have access to `p` and `q`.
        let (p_part, q_part) = rns;
        let p_res = self.sqrt_part(p_part, self.primes.p_half());
        let q_res = self.sqrt_part(q_part, self.primes.q_half());
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
        let a_mod_q = a_half.to_montgomery(&self.monty_params_mod_q);
        let x = ((b_mod_q.clone() - a_mod_q) * self.inv_p_mod_q.expose_secret()).retrieve();
        let a = a_half.into_wide();

        // Will not overflow since 0 <= x < q, and 0 <= a < p.
        a.checked_add(&self.primes.p_half().expose_secret().mul_wide(&x))
            .expect("Will not overflow since 0 <= x < q, and 0 <= a < p.")
    }

    /// Returns a random $w \in [0, N)$ such that $w$ is not a square modulo $N$,
    /// where $N$ is the public key
    /// (or, equivalently, such that the Jacobi symbol $(w|N) = -1$).
    pub fn random_nonsquare_residue(&self, rng: &mut impl CryptoRngCore) -> P::Uint {
        /*
        (The sampling method and the explanation by Thomas Pornin)

        Recall that `nonsquare_sampling_constant` $u$ is such that
        $u = -1 \mod p$ and $u = 1 \mod q$, so $u^2 = 1 \mod N$.

        For an $x \in \mathbb{Z}_N^*$ (that is, an invertible element),
        consider the set $S_x = {x, -x, u x, -u x}$.
        For any $x$ and $x^\prime$, then either $S_x = S_{x^\prime}$, or $S_x$ and $S_{x^\prime}$
        are completely disjoint: the sets $S_x$ make a partition of $\mathbb{Z}_N^*$.

        Moreover, exactly two of the four elements of $S_x$ is a square modulo $N$.
        If $x$ is the square in $S_x$, then the Jacobi symbols $(x|N)$ and $(-x|N)$ are both equal to 1,
        while the Jacobi symbols $(u x|N)$ and $(-u x|N)$ are both equal to -1.

        In order to get a uniform integer of Jacobi symbol -1, we need to make a uniform selection of $S_x$,
        which we get by selecting $y$ uniformly from $\mathbb{Z}_N^*$ and taking $x = y^2 \mod N$.
        After that, we select uniformly between $u x$ and $-u x$.
        */
        let y = self.public_key.modulus.random_quadratic_residue(rng);
        let b = Choice::from(rng.next_u32() as u8 & 1);
        let w = y * self.nonsquare_sampling_constant.expose_secret();
        P::UintMod::conditional_select(&w, &-w, b).retrieve()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicModulusWire<P>: Serialize"))]
#[serde(bound(deserialize = "for<'x> PublicModulusWire<P>: Deserialize<'x>"))]
pub(crate) struct PublicKeyPaillierWire<P: PaillierParams> {
    modulus: PublicModulusWire<P>,
}

impl<P: PaillierParams> PublicKeyPaillierWire<P> {
    fn new(primes: &SecretPrimesWire<P>) -> Self {
        Self {
            modulus: primes.modulus(),
        }
    }

    pub fn into_precomputed(self) -> PublicKeyPaillier<P> {
        PublicKeyPaillier::new(self.modulus.into_precomputed())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PublicKeyPaillier<P: PaillierParams> {
    modulus: PublicModulus<P>,
    monty_params_mod_n_squared: <P::WideUintMod as Monty>::Params,
    /// The minimal public key (for hashing purposes)
    public_key_wire: PublicKeyPaillierWire<P>,
}

impl<P: PaillierParams> PublicKeyPaillier<P> {
    fn new(modulus: PublicModulus<P>) -> Self {
        let monty_params_mod_n_squared = P::WideUintMod::new_params_vartime(
            Odd::new(modulus.modulus().square_wide()).expect("Square of odd number is odd"),
        );

        let public_key_wire = PublicKeyPaillierWire {
            modulus: modulus.to_wire(),
        };

        PublicKeyPaillier {
            modulus,
            monty_params_mod_n_squared,
            public_key_wire,
        }
    }

    pub fn as_wire(&self) -> &PublicKeyPaillierWire<P> {
        &self.public_key_wire
    }

    pub fn into_wire(self) -> PublicKeyPaillierWire<P> {
        self.public_key_wire.clone()
    }

    pub fn modulus(&self) -> &P::Uint {
        self.modulus.modulus()
    }

    pub fn modulus_bounded(&self) -> Bounded<P::Uint> {
        self.modulus.modulus_bounded()
    }

    pub fn modulus_nonzero(&self) -> NonZero<P::Uint> {
        self.modulus.modulus_nonzero()
    }

    pub fn modulus_wide_nonzero(&self) -> NonZero<P::WideUint> {
        NonZero::new(self.modulus.modulus().into_wide()).expect("the modulus is non-zero")
    }

    /// Returns precomputed parameters for integers modulo N
    pub fn monty_params_mod_n(&self) -> &<P::UintMod as Monty>::Params {
        self.modulus.monty_params_mod_n()
    }

    /// Returns precomputed parameters for integers modulo N^2
    pub fn monty_params_mod_n_squared(&self) -> &<P::WideUintMod as Monty>::Params {
        &self.monty_params_mod_n_squared
    }

    /// Finds an invertible group element via rejection sampling. Returns the
    /// element in Montgomery form.
    pub fn random_invertible_residue(&self, rng: &mut impl CryptoRngCore) -> P::UintMod {
        self.modulus.random_invertible_residue(rng)
    }
}

impl<P: PaillierParams> PartialEq for PublicKeyPaillier<P> {
    fn eq(&self, other: &Self) -> bool {
        self.modulus.eq(&other.modulus)
    }
}

impl<P: PaillierParams> Eq for PublicKeyPaillier<P> {}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_core::OsRng;
    use serde::Serialize;
    use serde_assert::Token;

    use super::{super::params::PaillierTest, SecretKeyPaillierWire};

    #[test]
    fn basics() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let _pk = sk.public_key();
    }

    #[test]
    fn debug_redacts_secrets() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng);

        let debug_output = format!("Sikrit {:?}", sk);
        assert_eq!(
            debug_output,
            concat![
                "Sikrit SecretKeyPaillierWire ",
                "{ primes: SecretPrimesWire { p: Secret<crypto_bigint::uint::Uint<8>>(...), ",
                "q: Secret<crypto_bigint::uint::Uint<8>>(...) } }",
            ]
        );
    }

    #[test]
    fn serialization_and_clone_works() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123456);
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut rng);

        let serializer = serde_assert::Serializer::builder().build();
        let sk_ser = sk.serialize(&serializer).unwrap();
        let expected_tokens = [
            Token::Struct {
                name: "SecretKeyPaillierWire",
                len: 1,
            },
            Token::Field("primes"),
            Token::Struct {
                name: "SecretPrimesWire",
                len: 2,
            },
            Token::Field("p"),
            Token::Str(
                concat![
                    "cf4ee6be31dbfa5fe153ec138abb8a8d8271386e6e359dd18f0ef4b8f7301391",
                    "2f58867d5d8fb0f30b1d96f215100ff97097b3baac10c8cc3aac969e7df3ac8e"
                ]
                .to_string(),
            ),
            Token::Field("q"),
            Token::Str(
                concat![
                    "732bbb2b9a150d2797ab52dde9dd00f467b6608d5c3161cca23711e754365752",
                    "51f55e9c3b34412388f592f71c638c73edf68a6af97aab03faff8c42357a8cd0"
                ]
                .to_string(),
            ),
            Token::StructEnd,
            Token::StructEnd,
        ];
        assert_eq!(sk_ser, expected_tokens);
    }
}
