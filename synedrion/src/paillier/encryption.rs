use core::{
    marker::PhantomData,
    ops::{Add, Mul},
};

use crypto_bigint::{
    modular::Retrieve,
    subtle::{Choice, ConditionallyNegatable, ConstantTimeGreater},
    Monty, Pow, ShrVartime,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    keys::{PublicKeyPaillier, SecretKeyPaillier},
    params::PaillierParams,
};
use crate::{
    tools::Secret,
    uint::{HasWide, PublicSigned, SecretSigned, SecretUnsigned, ToMontgomery},
};

/// A public randomizer-like quantity used in ZK proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MaskedRandomizer<P: PaillierParams>(P::Uint);

/// A ciphertext randomizer (an invertible element of $\mathbb{Z}_N$).
#[derive(Debug, Clone)]
pub(crate) struct Randomizer<P: PaillierParams> {
    randomizer: Secret<P::Uint>,
    randomizer_mod: Secret<P::UintMod>,
}

impl<P: PaillierParams> Randomizer<P> {
    fn new_mod(randomizer_mod: Secret<P::UintMod>) -> Self {
        let randomizer = randomizer_mod.retrieve();
        Self {
            randomizer,
            randomizer_mod,
        }
    }

    fn new(pk: &PublicKeyPaillier<P>, randomizer: Secret<P::Uint>) -> Self {
        let randomizer_mod = randomizer.to_montgomery(pk.monty_params_mod_n());
        Self {
            randomizer,
            randomizer_mod,
        }
    }

    pub fn random(rng: &mut impl CryptoRngCore, pk: &PublicKeyPaillier<P>) -> Self {
        let randomizer = Secret::init_with(|| pk.random_invertible_residue(rng));
        Self::new(pk, randomizer)
    }

    /// Expose this secret randomizer.
    ///
    /// Supposed to be used in certain error branches where it is needed to generate a malicious behavior evidence.
    pub fn expose(&self) -> P::Uint {
        *self.randomizer.expose_secret()
    }

    /// Converts the randomizer to a publishable form by masking it with another randomizer and a public exponent.
    pub fn to_masked(&self, coeff: &Self, exponent: &PublicSigned<P::Uint>) -> MaskedRandomizer<P> {
        MaskedRandomizer(
            (self.randomizer_mod.pow(exponent) * &coeff.randomizer_mod)
                .expose_secret()
                .retrieve(),
        )
    }
}

/// Paillier ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CiphertextWire<P: PaillierParams> {
    ciphertext: P::WideUint,
    phantom: PhantomData<P>,
}

impl<P: PaillierParams> CiphertextWire<P> {
    pub fn to_precomputed(&self, pk: &PublicKeyPaillier<P>) -> Ciphertext<P> {
        Ciphertext {
            pk: pk.clone(),
            ciphertext: self.ciphertext.to_montgomery(pk.monty_params_mod_n_squared()),
        }
    }
}

/// Paillier ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ciphertext<P: PaillierParams> {
    pk: PublicKeyPaillier<P>,
    ciphertext: P::WideUintMod,
}

impl<P: PaillierParams> Ciphertext<P> {
    pub fn public_key(&self) -> &PublicKeyPaillier<P> {
        &self.pk
    }

    /// Encrypts the plaintext with the provided randomizer.
    fn new_with_randomizer_inner(
        pk: &PublicKeyPaillier<P>,
        abs_plaintext: &SecretUnsigned<P::Uint>,
        randomizer: &Randomizer<P>,
        plaintext_is_negative: Choice,
    ) -> Self {
        // Technically if `abs_plaintext` is greater than the modulus of `pk`,
        // it will be effectively reduced modulo `pk`.
        // But some ZK proofs with `TestParams` may still supply a value larger than `pk`
        // because they are not planning on decrypting the resulting ciphertext;
        // they just construct an encryption of the same value in two different ways
        // and then compare the results.
        // (And the value can be larger than `pk` because of some restrictions on
        // `SchemeParameters`/`PaillierParameters` values in tests, which can only
        // be overcome by fixing #27 and using a small 32- or 64-bit curve for tests)

        // Calculate the ciphertext `C = (N + 1)^m * rho^N mod N^2`
        // where `N` is the Paillier composite modulus, `m` is the plaintext,
        // and `rho` is the randomizer.

        // Simplify `(N + 1)^m mod N^2 == 1 + m * N mod N^2`.
        // Since `m` can be negative, we calculate `m * N +- 1` (never overflows since `m < N`),
        // then conditionally negate modulo N^2

        let prod = abs_plaintext.mul_wide(pk.modulus());
        let mut prod_mod = prod.to_montgomery(pk.monty_params_mod_n_squared());
        prod_mod.conditional_negate(plaintext_is_negative);

        let factor1 = prod_mod + &P::WideUintMod::one(pk.monty_params_mod_n_squared().clone());

        let randomizer = randomizer.randomizer.to_wide();
        let pk_modulus = pk.modulus_signed();
        let factor2 = randomizer
            .to_montgomery(pk.monty_params_mod_n_squared())
            .pow(&pk_modulus);

        let ciphertext = *(factor1 * factor2).expose_secret();

        Self {
            pk: pk.clone(),
            ciphertext,
        }
    }

    fn new_public_with_randomizer_inner(
        pk: &PublicKeyPaillier<P>,
        abs_plaintext: &P::Uint,
        randomizer: &MaskedRandomizer<P>,
        plaintext_is_negative: bool,
    ) -> Self {
        // Same as `new_with_randomizer_inner`, but works on public data.

        let prod = abs_plaintext.mul_wide(pk.modulus());
        let mut prod_mod = prod.to_montgomery(pk.monty_params_mod_n_squared());
        if plaintext_is_negative {
            prod_mod = -prod_mod;
        }

        let factor1 = prod_mod + P::WideUintMod::one(pk.monty_params_mod_n_squared().clone());

        let randomizer = randomizer.0.to_wide();
        let pk_modulus = pk.modulus_signed();
        let factor2 = randomizer
            .to_montgomery(pk.monty_params_mod_n_squared())
            .pow(&pk_modulus);

        let ciphertext = factor1 * factor2;

        Self {
            pk: pk.clone(),
            ciphertext,
        }
    }

    /// Encrypts the plaintext with the provided randomizer.
    pub fn new_with_randomizer(
        pk: &PublicKeyPaillier<P>,
        plaintext: &SecretUnsigned<P::Uint>,
        randomizer: &Randomizer<P>,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, plaintext, randomizer, Choice::from(0))
    }

    pub fn new_with_randomizer_signed(
        pk: &PublicKeyPaillier<P>,
        plaintext: &SecretSigned<P::Uint>,
        randomizer: &Randomizer<P>,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, &plaintext.abs(), randomizer, plaintext.is_negative())
    }

    pub fn new_public_with_randomizer_signed(
        pk: &PublicKeyPaillier<P>,
        plaintext: &PublicSigned<P::Uint>,
        randomizer: &MaskedRandomizer<P>,
    ) -> Self {
        Self::new_public_with_randomizer_inner(pk, &plaintext.abs(), randomizer, plaintext.is_negative())
    }

    pub fn new_public_with_randomizer_wide(
        pk: &PublicKeyPaillier<P>,
        plaintext: &PublicSigned<P::WideUint>,
        randomizer: &MaskedRandomizer<P>,
    ) -> Self {
        let plaintext_reduced = P::Uint::try_from_wide(&(plaintext.abs() % pk.modulus_wide_nonzero()))
            .expect("the number within range after reducing modulo N");
        Self::new_public_with_randomizer_inner(pk, &plaintext_reduced, randomizer, plaintext.is_negative())
    }

    /// Encrypts the plaintext with a random randomizer.
    pub fn new(rng: &mut impl CryptoRngCore, pk: &PublicKeyPaillier<P>, plaintext: &SecretUnsigned<P::Uint>) -> Self {
        Self::new_with_randomizer(pk, plaintext, &Randomizer::random(rng, pk))
    }

    #[cfg(test)]
    pub fn new_signed(
        rng: &mut impl CryptoRngCore,
        pk: &PublicKeyPaillier<P>,
        plaintext: &SecretSigned<P::Uint>,
    ) -> Self {
        Self::new_with_randomizer_signed(pk, plaintext, &Randomizer::random(rng, pk))
    }

    /// Decrypts this ciphertext assuming that the plaintext is in range `[0, N)`.
    pub fn decrypt(&self, sk: &SecretKeyPaillier<P>) -> Secret<P::Uint> {
        assert_eq!(sk.public_key(), &self.pk);

        let pk = sk.public_key();
        let totient_wide = sk.totient_wide_unsigned();

        // Calculate the plaintext `m = ((C^phi mod N^2 - 1) / N) * mu mod N`,
        // where `m` is the plaintext, `C` is the ciphertext,
        // `N` is the Paillier composite modulus,
        // `phi` is the Euler totient of `N`, and `mu = phi^(-1) mod N`.

        // `C^phi mod N^2` may be 0 if `C == N`, which is very unlikely for large `N`.
        // Note that `C^phi mod N^2 / N < N`, so we can unwrap when converting to `Uint`
        // (because `N` itself fits into `Uint`).

        // Calculate `C^phi mod N^2`. The result is already secret.
        let t = Secret::init_with(|| self.ciphertext.pow(&totient_wide));
        let one = P::WideUintMod::one(pk.monty_params_mod_n_squared().clone());
        let x = (t - &one).retrieve() / pk.modulus_wide_nonzero();
        let x = Secret::init_with(|| {
            P::Uint::try_from_wide(x.expose_secret()).expect("the value is within `Uint` limtis by construction")
        });

        let x_mod = x.to_montgomery(pk.monty_params_mod_n());

        (x_mod * sk.inv_totient()).retrieve()
    }

    /// Decrypts this ciphertext assuming that the plaintext is in range `[-N/2, N/2)`.
    pub fn decrypt_signed(&self, sk: &SecretKeyPaillier<P>) -> SecretSigned<P::Uint> {
        assert_eq!(sk.public_key(), &self.pk);

        let pk = sk.public_key();

        // Note that this is in range `[0, N)`
        let positive_result = self.decrypt(sk);

        // Can't define a `Sub<Secret>` for `Uint`, so have to re-wrap manually.
        let negative_result = Secret::init_with(|| *pk.modulus() - positive_result.expose_secret());
        let is_negative = positive_result
            .expose_secret()
            .ct_gt(&pk.modulus().wrapping_shr_vartime(1));

        let uint_result = Secret::<P::Uint>::conditional_select(&positive_result, &negative_result, is_negative);
        let result = SecretSigned::new_from_unsigned(uint_result, P::MODULUS_BITS - 1)
            .expect("the value is within `[-2^(MODULUS_BITS-1), 2^(MODULUS_BITS-1)]` by construction");

        SecretSigned::conditional_select(&result, &-result.clone(), is_negative)
    }

    /// Derive the randomizer used to create this ciphertext.
    pub fn derive_randomizer(&self, sk: &SecretKeyPaillier<P>) -> Randomizer<P> {
        assert_eq!(sk.public_key(), &self.pk);

        let pk = sk.public_key();

        // NOTE: the paper has a more complicated formula, but this one works just as well.

        // Remember that the ciphertext
        //     C = (N + 1)^m * rho^N mod N^2
        //     = (1 + m * N) * rho^N mod N^2`,
        //     = rho^N + m * N * rho^N + k * N^2,
        // where `k` is some integer.
        // Therefore `C mod N = rho^N mod N`.
        let ciphertext_mod_n = P::Uint::try_from_wide(&(self.ciphertext.retrieve() % pk.modulus_wide_nonzero()))
            .expect("a value reduced modulo N fits into `Uint`");
        let ciphertext_mod_n = ciphertext_mod_n.to_montgomery(pk.monty_params_mod_n());

        // To isolate `rho`, calculate `(rho^N)^(N^(-1)) mod N`.
        // The order of `Z_N` is `phi(N)`, so the inversion in the exponent is modulo `phi(N)`.
        let sk_inv_modulus = sk.inv_modulus();
        let randomizer_mod = Secret::init_with(|| ciphertext_mod_n.pow(sk_inv_modulus));

        Randomizer::new_mod(randomizer_mod)
    }

    // Note: while it is true that `enc(x) (*) rhs == enc((x * rhs) mod N)`,
    // reducing the signed `rhs` modulo `N` will result in a ciphertext with a different randomizer
    // compared to what we would get if we used the signed `rhs` faithfully in the original formula.
    // So if we want to replicate the Paillier encryption manually and get the same ciphertext
    // (e.g. in the P_enc sigma-protocol), we need to process the sign correctly.
    fn homomorphic_mul<V>(self, rhs: &V) -> Self
    where
        P::WideUintMod: Pow<V>,
    {
        Self {
            pk: self.pk,
            ciphertext: self.ciphertext.pow(rhs),
        }
    }

    fn homomorphic_mul_ref<V>(&self, rhs: &V) -> Self
    where
        P::WideUintMod: Pow<V>,
    {
        Self {
            pk: self.pk.clone(),
            ciphertext: self.ciphertext.pow(rhs),
        }
    }

    fn homomorphic_add(self, rhs: &Self) -> Self {
        assert!(self.pk == rhs.pk);
        Self {
            pk: self.pk,
            ciphertext: self.ciphertext * rhs.ciphertext,
        }
    }

    pub fn mul_masked_randomizer(self, randomizer: &MaskedRandomizer<P>) -> Self {
        let randomizer_mod = randomizer
            .0
            .to_wide()
            .to_montgomery(self.pk.monty_params_mod_n_squared());
        let pk_modulus = self.pk.modulus_signed();
        let ciphertext = self.ciphertext * randomizer_mod.pow(&pk_modulus);
        Self {
            pk: self.pk,
            ciphertext,
        }
    }

    pub fn mul_randomizer(self, randomizer: &Randomizer<P>) -> Self {
        let randomizer_mod = randomizer
            .randomizer
            .to_wide()
            .to_montgomery(self.pk.monty_params_mod_n_squared());
        let pk_modulus = self.pk.modulus_signed();
        let ciphertext = self.ciphertext * randomizer_mod.pow(&pk_modulus).expose_secret();
        Self {
            pk: self.pk,
            ciphertext,
        }
    }

    pub fn to_wire(&self) -> CiphertextWire<P> {
        CiphertextWire {
            ciphertext: self.ciphertext.retrieve(),
            phantom: PhantomData,
        }
    }
}

impl<P: PaillierParams> Add<Ciphertext<P>> for Ciphertext<P> {
    type Output = Ciphertext<P>;
    fn add(self, rhs: Ciphertext<P>) -> Ciphertext<P> {
        self + &rhs
    }
}

impl<P: PaillierParams> Add<&Ciphertext<P>> for Ciphertext<P> {
    type Output = Ciphertext<P>;
    fn add(self, rhs: &Ciphertext<P>) -> Ciphertext<P> {
        self.homomorphic_add(rhs)
    }
}

impl<P: PaillierParams, V> Mul<&V> for Ciphertext<P>
where
    P::WideUintMod: Pow<V>,
{
    type Output = Ciphertext<P>;
    fn mul(self, rhs: &V) -> Ciphertext<P> {
        self.homomorphic_mul(rhs)
    }
}

impl<P: PaillierParams, V> Mul<&V> for &Ciphertext<P>
where
    P::WideUintMod: Pow<V>,
{
    type Output = Ciphertext<P>;
    fn mul(self, rhs: &V) -> Ciphertext<P> {
        self.homomorphic_mul_ref(rhs)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{
        subtle::ConditionallySelectable, Encoding, Integer, NonZero, RandomMod, ShrVartime, WrappingSub,
    };
    use rand_core::OsRng;
    use zeroize::Zeroize;

    use super::{
        super::{params::PaillierTest, PaillierParams, SecretKeyPaillierWire},
        Ciphertext, Randomizer,
    };
    use crate::{
        tools::Secret,
        uint::{HasWide, SecretSigned, SecretUnsigned},
    };

    fn mul_mod<T>(lhs: &T, rhs: &SecretSigned<T>, modulus: &NonZero<T>) -> T
    where
        T: Zeroize + Integer + HasWide + crypto_bigint::Bounded + Encoding + ConditionallySelectable,
    {
        // There may be more efficient ways to do this (e.g. Barrett reduction),
        // but it's only used in tests.

        // Note that modulus here may be even, so we can't use Montgomery representation

        let wide_product = lhs.mul_wide(rhs.abs().expose_secret());
        let wide_modulus = modulus.as_ref().to_wide();
        let result = T::try_from_wide(&(wide_product % NonZero::new(wide_modulus).unwrap())).unwrap();
        if rhs.is_negative().into() {
            modulus.as_ref().checked_sub(&result).unwrap()
        } else {
            result
        }
    }

    fn reduce<P: PaillierParams>(val: &SecretSigned<P::Uint>, modulus: &NonZero<P::Uint>) -> SecretSigned<P::Uint> {
        let result = *val.abs().expose_secret() % modulus;
        let twos_complement_result = if result > modulus.as_ref().wrapping_shr_vartime(1) {
            result.wrapping_sub(modulus.as_ref())
        } else {
            result
        };
        let signed_result =
            SecretSigned::new_from_unsigned(Secret::init_with(|| twos_complement_result), P::MODULUS_BITS - 1).unwrap();
        if val.is_negative().into() {
            -signed_result
        } else {
            signed_result
        }
    }

    #[test]
    fn roundtrip() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();
        let plaintext = SecretUnsigned::new(
            Secret::init_with(|| <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero())),
            PaillierTest::MODULUS_BITS,
        )
        .unwrap();
        let ciphertext = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext);
        let plaintext_back = ciphertext.decrypt(&sk);
        assert_eq!(plaintext.expose_secret(), plaintext_back.expose_secret());

        let ciphertext_wire = ciphertext.to_wire();
        let ciphertext_back = ciphertext_wire.to_precomputed(pk);
        assert_eq!(ciphertext, ciphertext_back);
    }

    #[test]
    fn signed_roundtrip() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();
        let plaintext = SecretSigned::random_in_exp_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 2);
        let ciphertext = Ciphertext::new_signed(&mut OsRng, pk, &plaintext);
        let plaintext_back = ciphertext.decrypt_signed(&sk);
        let plaintext_reduced = reduce::<PaillierTest>(&plaintext, &pk.modulus_nonzero());
        assert_eq!(plaintext_reduced.to_public(), plaintext_back.to_public());
    }

    #[test]
    fn derive_randomizer() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();
        let plaintext = SecretUnsigned::new(
            Secret::init_with(|| <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero())),
            PaillierTest::MODULUS_BITS,
        )
        .unwrap();
        let randomizer = Randomizer::random(&mut OsRng, pk);
        let ciphertext = Ciphertext::<PaillierTest>::new_with_randomizer(pk, &plaintext, &randomizer);
        let randomizer_back = ciphertext.derive_randomizer(&sk);
        assert_eq!(randomizer.expose(), randomizer_back.expose());
    }

    #[test]
    fn homomorphic_mul() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();
        let plaintext = SecretUnsigned::new(
            Secret::init_with(|| <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero())),
            PaillierTest::MODULUS_BITS,
        )
        .unwrap();
        let ciphertext = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext);

        let coeff = SecretSigned::random_in_exp_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 2);
        let new_ciphertext = ciphertext * &coeff;
        let new_plaintext = new_ciphertext.decrypt(&sk);

        assert_eq!(
            &mul_mod(plaintext.expose_secret(), &coeff, &pk.modulus_nonzero()),
            new_plaintext.expose_secret()
        );
    }

    #[test]
    fn homomorphic_add() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let plaintext1 = SecretUnsigned::new(
            Secret::init_with(|| <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero())),
            PaillierTest::MODULUS_BITS,
        )
        .unwrap();
        let ciphertext1 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext1);

        let plaintext2 = SecretUnsigned::new(
            Secret::init_with(|| <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero())),
            PaillierTest::MODULUS_BITS,
        )
        .unwrap();
        let ciphertext2 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext2);

        let new_ciphertext = ciphertext1 + ciphertext2;
        let new_plaintext = new_ciphertext.decrypt(&sk);

        assert_eq!(
            &plaintext1
                .expose_secret()
                .add_mod(plaintext2.expose_secret(), pk.modulus()),
            new_plaintext.expose_secret()
        );
    }

    #[test]
    fn affine_transform() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let plaintext1 = SecretUnsigned::new(
            Secret::init_with(|| <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero())),
            PaillierTest::MODULUS_BITS,
        )
        .unwrap();
        let plaintext2 =
            SecretSigned::random_in_exp_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 2);
        let plaintext3 = SecretUnsigned::new(
            Secret::init_with(|| <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero())),
            PaillierTest::MODULUS_BITS,
        )
        .unwrap();

        let ciphertext1 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext1);
        let ciphertext3 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext3);
        let result = ciphertext1 * &plaintext2 + ciphertext3;

        let plaintext_back = result.decrypt(&sk);
        assert_eq!(
            &mul_mod(plaintext1.expose_secret(), &plaintext2, &pk.modulus_nonzero())
                .add_mod(plaintext3.expose_secret(), pk.modulus()),
            plaintext_back.expose_secret()
        );
    }
}
