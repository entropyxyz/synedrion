use core::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

use crypto_bigint::{
    modular::Retrieve,
    subtle::{Choice, ConditionallyNegatable},
    Invert, Monty,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    keys::{PublicKeyPaillier, SecretKeyPaillier},
    params::PaillierParams,
};
use crate::{
    tools::Secret,
    uint::{Exponentiable, Extendable, PublicSigned, PublicUint, SecretSigned, SecretUnsigned, ToMontgomery},
};

/// A public randomizer-like quantity used in ZK proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MaskedRandomizer<P: PaillierParams>(PublicUint<P::Uint>);

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

    pub fn random(rng: &mut dyn CryptoRngCore, pk: &PublicKeyPaillier<P>) -> Self {
        let randomizer = Secret::init_with(|| pk.random_invertible_residue(rng));
        Self::new(pk, randomizer)
    }

    /// Converts the randomizer to a publishable form by masking it with another randomizer and a public exponent.
    ///
    /// That is, for a randomizer `rho` it returns `rho^exponent * coeff`.
    pub fn to_masked(&self, coeff: &Self, exponent: &PublicSigned<P::Uint>) -> MaskedRandomizer<P> {
        MaskedRandomizer(
            (self.randomizer_mod.pow(exponent) * &coeff.randomizer_mod)
                .expose_secret()
                .retrieve()
                .into(),
        )
    }
}

/// Paillier ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CiphertextWire<P: PaillierParams> {
    ciphertext: PublicUint<P::WideUint>,
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
        abs_plaintext: &SecretUnsigned<P::WideUint>,
        randomizer: &Randomizer<P>,
        plaintext_is_negative: Choice,
    ) -> Self {
        // Calculate the ciphertext `C = (N + 1)^m * rho^N mod N^2`
        // where `N` is the Paillier composite modulus, `m` is the plaintext,
        // and `rho` is the randomizer.

        // Simplify `(N + 1)^m mod N^2 == 1 + m * N mod N^2`.
        // Since `m` can be negative, we calculate `m * N ± 1` (never overflows since `m < N`),
        // then conditionally negate modulo N^2

        // Since most of the time the plaintext is just `Uint`, another way to calculate it
        // is the wide multiplication by the modulus and then conversion to Montgomery.
        let abs_plaintext = abs_plaintext.to_montgomery(pk.monty_params_mod_n_squared());
        let mut prod_mod = abs_plaintext * pk.modulus_mod_modulus_squared();

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
        abs_plaintext: &P::WideUint,
        randomizer: &MaskedRandomizer<P>,
        plaintext_is_negative: bool,
    ) -> Self {
        // Same as `new_with_randomizer_inner`, but works on public data.

        let abs_plaintext = abs_plaintext.to_montgomery(pk.monty_params_mod_n_squared());
        let mut prod_mod = abs_plaintext * pk.modulus_mod_modulus_squared();
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
        plaintext: &SecretSigned<P::Uint>,
        randomizer: &Randomizer<P>,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, &plaintext.abs().to_wide(), randomizer, plaintext.is_negative())
    }

    pub fn new_wide_with_randomizer(
        pk: &PublicKeyPaillier<P>,
        plaintext: &SecretSigned<P::WideUint>,
        randomizer: &Randomizer<P>,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, &plaintext.abs(), randomizer, plaintext.is_negative())
    }

    pub fn new_public_with_randomizer(
        pk: &PublicKeyPaillier<P>,
        plaintext: &PublicSigned<P::Uint>,
        randomizer: &MaskedRandomizer<P>,
    ) -> Self {
        Self::new_public_with_randomizer_inner(pk, &plaintext.abs().to_wide(), randomizer, plaintext.is_negative())
    }

    pub fn new_public_wide_with_randomizer(
        pk: &PublicKeyPaillier<P>,
        plaintext: &PublicSigned<P::WideUint>,
        randomizer: &MaskedRandomizer<P>,
    ) -> Self {
        Self::new_public_with_randomizer_inner(pk, &plaintext.abs(), randomizer, plaintext.is_negative())
    }

    /// Encrypts the plaintext with a random randomizer.
    #[cfg(any(test, feature = "private-benches"))]
    pub fn new(rng: &mut dyn CryptoRngCore, pk: &PublicKeyPaillier<P>, plaintext: &SecretSigned<P::Uint>) -> Self {
        Self::new_with_randomizer(pk, plaintext, &Randomizer::random(rng, pk))
    }

    /// Decrypts this ciphertext assuming that the plaintext is in range `[-N/2, N/2]`.
    pub fn decrypt(&self, sk: &SecretKeyPaillier<P>) -> SecretSigned<P::Uint> {
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

        // Note that this is in range `[0, N)`
        let positive_result = (x_mod * sk.inv_totient()).retrieve();

        SecretSigned::new_modulo(positive_result, &pk.modulus_nonzero(), P::MODULUS_BITS)
            .expect("the value is within `[0, N)` by construction and the modulus fits into `P::Uint`")
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

    fn homomorphic_neg_ref(&self) -> Self {
        Self {
            pk: self.pk.clone(),
            // `C = (N + 1)^m * rho^N mod N^2`; `(N + 1)` is invertible `mod N^2`,
            // and the randomizer `rho` was sampled to be invertible `mod N`.
            ciphertext: Option::from(self.ciphertext.invert()).expect("the ciphertext is invertible by construction"),
        }
    }

    // Note: while it is true that `enc(x) (*) rhs == enc((x * rhs) mod N)`,
    // reducing the signed `rhs` modulo `N` will result in a ciphertext with a different randomizer
    // compared to what we would get if we used the signed `rhs` faithfully in the original formula.
    // So if we want to replicate the Paillier encryption manually and get the same ciphertext
    // (e.g. in the P_enc sigma-protocol), we need to process the sign correctly.
    fn homomorphic_mul<V>(self, rhs: &V) -> Self
    where
        P::WideUintMod: Exponentiable<V>,
    {
        Self {
            pk: self.pk,
            ciphertext: self.ciphertext.pow(rhs),
        }
    }

    fn homomorphic_mul_ref<V>(&self, rhs: &V) -> Self
    where
        P::WideUintMod: Exponentiable<V>,
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

    fn homomorphic_add_ref(&self, rhs: &Self) -> Self {
        assert!(self.pk == rhs.pk);
        Self {
            pk: self.pk.clone(),
            ciphertext: self.ciphertext * rhs.ciphertext,
        }
    }

    pub fn to_wire(&self) -> CiphertextWire<P> {
        CiphertextWire {
            ciphertext: self.ciphertext.retrieve().into(),
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

impl<P: PaillierParams> Sub<&Ciphertext<P>> for Ciphertext<P> {
    type Output = Ciphertext<P>;
    fn sub(self, rhs: &Ciphertext<P>) -> Ciphertext<P> {
        self.homomorphic_add(&rhs.homomorphic_neg_ref())
    }
}

impl<P: PaillierParams> Add<&Ciphertext<P>> for &Ciphertext<P> {
    type Output = Ciphertext<P>;
    fn add(self, rhs: &Ciphertext<P>) -> Ciphertext<P> {
        self.homomorphic_add_ref(rhs)
    }
}

impl<P: PaillierParams, V> Mul<&V> for Ciphertext<P>
where
    P::WideUintMod: Exponentiable<V>,
{
    type Output = Ciphertext<P>;
    fn mul(self, rhs: &V) -> Ciphertext<P> {
        self.homomorphic_mul(rhs)
    }
}

impl<P: PaillierParams, V> Mul<&V> for &Ciphertext<P>
where
    P::WideUintMod: Exponentiable<V>,
{
    type Output = Ciphertext<P>;
    fn mul(self, rhs: &V) -> Ciphertext<P> {
        self.homomorphic_mul_ref(rhs)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{subtle::ConditionallySelectable, AddMod, Bounded, Integer, NonZero};
    use rand_core::OsRng;
    use zeroize::Zeroize;

    use super::{
        super::{PaillierParams, SecretKeyPaillierWire},
        Ciphertext, Randomizer,
    };
    use crate::{
        dev::PaillierTest,
        tools::Secret,
        uint::{Extendable, MulWide, SecretSigned},
    };

    /// Calculates `val` modulo `modulus`, returning the result in range `[0, modulus)`.
    fn reduce_unsigned<T>(val: &SecretSigned<T>, modulus: &NonZero<T>) -> T
    where
        T: Zeroize + Integer + Bounded + ConditionallySelectable,
    {
        let abs_result = *val.abs().expose_secret() % modulus;
        if (val.is_negative() & !abs_result.is_zero()).into() {
            *modulus.as_ref() - abs_result
        } else {
            abs_result
        }
    }

    /// Calculates `val` modulo `modulus`, returning the result in range `[-N/2, N/2]`
    fn reduce<P: PaillierParams>(val: &SecretSigned<P::Uint>, modulus: &NonZero<P::Uint>) -> SecretSigned<P::Uint> {
        SecretSigned::new_modulo(
            Secret::init_with(|| reduce_unsigned(val, modulus)),
            modulus,
            P::MODULUS_BITS,
        )
        .unwrap()
    }

    /// Calculates `lhs * rhs` modulo `modulus`, returning the result in range `[-N/2, N/2]`
    fn mul_mod<P: PaillierParams>(
        lhs: &SecretSigned<P::Uint>,
        rhs: &SecretSigned<P::Uint>,
        modulus: &NonZero<P::Uint>,
    ) -> SecretSigned<P::Uint> {
        // There may be more efficient ways to do this (e.g. Barrett reduction),
        // but it's only used in tests.

        let lhs = reduce_unsigned(lhs, modulus);
        let rhs = reduce_unsigned(rhs, modulus);
        let wide_product = lhs.mul_wide(&rhs);
        let wide_modulus = modulus.as_ref().to_wide();
        let result = P::Uint::try_from_wide(&(wide_product % NonZero::new(wide_modulus).unwrap())).unwrap();
        SecretSigned::new_modulo(Secret::init_with(|| result), modulus, P::MODULUS_BITS).unwrap()
    }

    /// Calculates `lhs + rhs` modulo `modulus`, returning the result in range `[-N/2, N/2]`
    fn add_mod<P: PaillierParams>(
        lhs: &SecretSigned<P::Uint>,
        rhs: &SecretSigned<P::Uint>,
        modulus: &NonZero<P::Uint>,
    ) -> SecretSigned<P::Uint> {
        let lhs = reduce_unsigned(lhs, modulus);
        let rhs = reduce_unsigned(rhs, modulus);
        let sum = lhs.add_mod(&rhs, modulus);
        SecretSigned::new_modulo(Secret::init_with(|| sum), modulus, P::MODULUS_BITS).unwrap()
    }

    #[test]
    fn signed_roundtrip() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();
        let plaintext =
            SecretSigned::random_in_exponent_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 1);
        let ciphertext = Ciphertext::new(&mut OsRng, pk, &plaintext);
        let plaintext_back = ciphertext.decrypt(&sk);
        let plaintext_reduced = reduce::<PaillierTest>(&plaintext, &pk.modulus_nonzero());
        assert_eq!(plaintext_reduced.to_public(), plaintext_back.to_public());
    }

    #[test]
    fn derive_randomizer() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();
        let plaintext =
            SecretSigned::random_in_exponent_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 1);
        let randomizer = Randomizer::random(&mut OsRng, pk);
        let ciphertext = Ciphertext::<PaillierTest>::new_with_randomizer(pk, &plaintext, &randomizer);
        let randomizer_back = ciphertext.derive_randomizer(&sk);
        assert_eq!(
            randomizer.randomizer.expose_secret(),
            randomizer_back.randomizer.expose_secret()
        );
    }

    #[test]
    fn homomorphic_mul() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();
        let plaintext =
            SecretSigned::random_in_exponent_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 1);
        let ciphertext = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext);

        let coeff =
            SecretSigned::random_in_exponent_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 1);
        let new_ciphertext = ciphertext * &coeff;
        let new_plaintext = new_ciphertext.decrypt(&sk);
        assert_eq!(
            mul_mod::<PaillierTest>(&plaintext, &coeff, &pk.modulus_nonzero()).to_public(),
            new_plaintext.to_public()
        );
    }

    #[test]
    fn homomorphic_add() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let plaintext1 =
            SecretSigned::random_in_exponent_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 1);
        let ciphertext1 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext1);

        let plaintext2 =
            SecretSigned::random_in_exponent_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 1);
        let ciphertext2 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext2);

        let new_ciphertext = ciphertext1 + ciphertext2;
        let new_plaintext = new_ciphertext.decrypt(&sk);

        assert_eq!(
            add_mod::<PaillierTest>(&plaintext1, &plaintext2, &pk.modulus_nonzero()).to_public(),
            new_plaintext.to_public()
        );
    }

    #[test]
    fn affine_transform() {
        let sk = SecretKeyPaillierWire::<PaillierTest>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let plaintext1 =
            SecretSigned::random_in_exponent_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 1);
        let plaintext2 =
            SecretSigned::random_in_exponent_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 1);
        let plaintext3 =
            SecretSigned::random_in_exponent_range(&mut OsRng, <PaillierTest as PaillierParams>::Uint::BITS - 1);

        let ciphertext1 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext1);
        let ciphertext3 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext3);
        let new_ciphertext = ciphertext1 * &plaintext2 + ciphertext3;

        let new_plaintext = new_ciphertext.decrypt(&sk);
        assert_eq!(
            add_mod::<PaillierTest>(
                &mul_mod::<PaillierTest>(&plaintext1, &plaintext2, &pk.modulus_nonzero()),
                &plaintext3,
                &pk.modulus_nonzero()
            )
            .to_public(),
            new_plaintext.to_public()
        );
    }
}
