use core::fmt::Debug;

use crypto_bigint::{
    modular::Retrieve,
    subtle::{Choice, ConditionallySelectable},
    CheckedAdd, CheckedSub, Integer, InvMod, Invert, Monty, NonZero, Odd, PowBoundedExp, ShrVartime, Square,
    WrappingAdd,
};
use digest::XofReader;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    params::PaillierParams,
    rsa::{PublicModulus, PublicModulusWire, SecretPrimes, SecretPrimesWire},
};
use crate::{
    tools::Secret,
    uint::{HasWide, PublicSigned, SecretSigned, SecretUnsigned, ToMontgomery},
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
    inv_modulus: SecretUnsigned<P::Uint>,
    /// $p^{-1} \mod q$, a constant used when joining an RNS-represented number using Garner's algorithm.
    inv_p_mod_q: Secret<P::HalfUintMod>,
    // $u$ such that $u = -1 \mod p$ and $u = 1 \mod q$. Used for sampling of non-square residues.
    nonsquare_sampling_constant: Secret<P::UintMod>,
    // TODO (#162): these should be secret, but they are not zeroizable.
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

        let monty_params_mod_p = P::HalfUintMod::new_params_vartime(primes.p_half_odd().expose_secret().clone());
        let monty_params_mod_q = P::HalfUintMod::new_params_vartime(primes.q_half_odd().expose_secret().clone());

        let inv_totient = Secret::init_with(|| {
            primes
                .totient()
                .expose_secret()
                .to_montgomery(modulus.monty_params_mod_n())
                .invert()
                .expect(concat![
                    "The modulus is pq. ϕ(pq) = (p-1)(q-1) is invertible mod pq because ",
                    "neither (p-1) nor (q-1) share factors with pq."
                ])
        });

        let inv_modulus = SecretUnsigned::new(
            Secret::init_with(|| {
                modulus
                    .modulus()
                    .inv_mod(primes.totient().expose_secret())
                    .expect("pq is invertible mod ϕ(pq) because gcd(pq, (p-1)(q-1)) = 1")
            }),
            P::MODULUS_BITS,
        )
        .expect("We assume `P::MODULUS_BITS` is properly configured");

        let p_mod = primes.p_half().to_montgomery(&monty_params_mod_q);
        let inv_p_mod_q = Secret::init_with(|| {
            p_mod
                .expose_secret()
                .invert()
                .expect("All non-zero integers mod a prime have a multiplicative inverse")
        });

        // Calculate $u$ such that $u = -1 \mod p$ and $u = 1 \mod q$.
        // Using one step of Garner's algorithm:
        // $u = p - 1 + p (2 p^{-1} - 1 \mod q)$

        // Calculate $t = 2 p^{-1} - 1 \mod q$

        let one = Secret::init_with(|| {
            // TODO (#162): `monty_params_mod_q` is cloned here and can remain on the stack.
            P::HalfUintMod::one(monty_params_mod_q.clone())
        });
        let t = (&inv_p_mod_q + &inv_p_mod_q - one).retrieve();

        // Calculate $u$
        // I am not entirely sure if it can be used to learn something about `p` and `q`,
        // so just to be on the safe side it lives in the secret key.

        let u = Secret::init_with(|| t.expose_secret().mul_wide(primes.p_half().expose_secret()));
        let u = Secret::init_with(|| {
            u.expose_secret()
                .checked_add(primes.p().expose_secret())
                .expect("does not overflow by construction")
        });
        let u = Secret::init_with(|| {
            u.expose_secret()
                .checked_sub(&<P::Uint as Integer>::one())
                .expect("does not overflow by construction")
        });
        let nonsquare_sampling_constant =
            Secret::init_with(|| P::UintMod::new(*u.expose_secret(), modulus.monty_params_mod_n().clone()));

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

    pub fn p_signed(&self) -> SecretSigned<P::Uint> {
        self.primes.p_signed()
    }

    pub fn q_signed(&self) -> SecretSigned<P::Uint> {
        self.primes.q_signed()
    }

    /// Returns Euler's totient function (`φ(n)`) of the modulus, wrapped in a [`Secret`].
    pub fn totient_wide_unsigned(&self) -> SecretUnsigned<P::WideUint> {
        self.primes.totient_wide_unsigned()
    }

    /// Returns $\phi(N)^{-1} \mod N$
    pub fn inv_totient(&self) -> &Secret<P::UintMod> {
        &self.inv_totient
    }

    /// Returns $N^{-1} \mod \phi(N)$
    pub fn inv_modulus(&self) -> &SecretUnsigned<P::Uint> {
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
        let p_rem_half = P::HalfUint::try_from_wide(&p_rem).expect("`p` fits into `HalfUint`");
        let q_rem_half = P::HalfUint::try_from_wide(&q_rem).expect("`q` fits into `HalfUint`");

        // TODO (#162): `monty_params_mod_q` is cloned here and can remain on the stack.
        let p_rem_mod = p_rem_half.to_montgomery(&self.monty_params_mod_p);
        let q_rem_mod = q_rem_half.to_montgomery(&self.monty_params_mod_q);

        (p_rem_mod, q_rem_mod)
    }

    fn sqrt_part(&self, x: &P::HalfUintMod, modulus: &Secret<P::HalfUint>) -> Option<P::HalfUintMod> {
        // Both `p` and `q` are safe primes, so they're 3 mod 4.
        // This means that if square root exists, it must be of the form `+/- x^((modulus+1)/4)`.
        // Also it means that `(modulus+1)/4 == modulus/4+1`
        // (this will help avoid a possible overflow).
        let power = Secret::init_with(|| {
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
        let a_mod_q = a_half.clone().to_montgomery(&self.monty_params_mod_q);
        let x = ((b_mod_q.clone() - a_mod_q) * self.inv_p_mod_q.expose_secret()).retrieve();
        let a = a_half.to_wide();

        // Will not overflow since 0 <= x < q, and 0 <= a < p.
        a.checked_add(&self.primes.p_half().expose_secret().mul_wide(&x))
            .expect("Will not overflow since 0 <= x < q, and 0 <= a < p.")
    }

    /// Returns a random invertible $w ∈ [0, N)$ such that $w$ is not a square modulo $N$,
    /// where $N$ is the public key
    /// (or, equivalently, such that the Jacobi symbol $(w|N) = -1$).
    pub fn random_nonsquare_residue(&self, rng: &mut impl CryptoRngCore) -> P::Uint {
        /*
        (The sampling method and the explanation by Thomas Pornin)

        Recall that `nonsquare_sampling_constant` $u$ is such that
        $u = -1 \mod p$ and $u = 1 \mod q$, so $u^2 = 1 \mod N$.

        For an $x ∈ \mathbb{Z}_N^*$ (that is, an invertible element),
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

        // Note that since `y` and `u` are invertible
        // (`y` is selected that way, and `u` is not a multiple of either `p` or `q`),
        // the result will be invertible as well.
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
            Odd::new(modulus.modulus().mul_wide(modulus.modulus())).expect("Square of odd number is odd"),
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

    pub fn modulus_signed(&self) -> PublicSigned<P::WideUint> {
        self.modulus.modulus_signed()
    }

    pub fn modulus_nonzero(&self) -> NonZero<P::Uint> {
        self.modulus.modulus_nonzero()
    }

    pub fn modulus_wide_nonzero(&self) -> NonZero<P::WideUint> {
        NonZero::new(self.modulus.modulus().to_wide()).expect("the modulus is non-zero")
    }

    /// Returns precomputed parameters for integers modulo N
    pub fn monty_params_mod_n(&self) -> &<P::UintMod as Monty>::Params {
        self.modulus.monty_params_mod_n()
    }

    /// Returns precomputed parameters for integers modulo N^2
    pub fn monty_params_mod_n_squared(&self) -> &<P::WideUintMod as Monty>::Params {
        &self.monty_params_mod_n_squared
    }

    /// Returns a uniformly chosen number in range $[0, N)$ such that it is invertible modulo $N$, in Montgomery form.
    pub fn random_invertible_residue(&self, rng: &mut impl CryptoRngCore) -> P::Uint {
        self.modulus.random_invertible_residue(rng)
    }

    /// Returns a number in range $[0, N)$ such that it is invertible modulo $N$, in Montgomery form,
    /// deterministically derived from an extensible output hash function.
    pub fn invertible_residue_from_xof_reader(&self, reader: &mut impl XofReader) -> P::Uint {
        self.modulus.invertible_residue_from_xof_reader(reader)
    }
}

impl<P: PaillierParams> PartialEq for PublicKeyPaillier<P> {
    fn eq(&self, rhs: &Self) -> bool {
        self.modulus.eq(&rhs.modulus)
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
                    "e3b7608d5c3161cca23711e75436575251f55e9c3b34412388f592f71c638c73",
                    "edf68a6af97aab03faff8c42357a8c50fb2110f1c12d8628debd5eefb0f676f3"
                ]
                .to_string(),
            ),
            Token::Field("q"),
            Token::Str(
                concat![
                    "17ea88a0e3187f0353c7c092f708369f5c6267e30c2a4c23a2eae9b524ffe0ed",
                    "227fc2a20e965b6f697f913fcc281e5bde33fc435391bd3650d5950d5407db92"
                ]
                .to_string(),
            ),
            Token::StructEnd,
            Token::StructEnd,
        ];
        assert_eq!(sk_ser, expected_tokens);
    }
}
