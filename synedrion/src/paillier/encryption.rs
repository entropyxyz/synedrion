use alloc::boxed::Box;
use core::marker::PhantomData;
use core::ops::{Add, Mul};

use rand_core::CryptoRngCore;
use secrecy::{CloneableSecret, ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::keys::{PublicKeyPaillierPrecomputed, SecretKeyPaillierPrecomputed};
use super::params::PaillierParams;
use crate::uint::{
    subtle::{Choice, ConditionallyNegatable, ConditionallySelectable},
    Bounded, HasWide, NonZero, Retrieve, Signed, UintLike, UintModLike,
};

// A ciphertext randomizer (an invertible element of $\mathbb{Z}_N$).
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop, Default, Zeroize)]
pub(crate) struct Randomizer<P: PaillierParams>(P::Uint);

impl<P: PaillierParams> Randomizer<P> {
    pub fn random(rng: &mut impl CryptoRngCore, pk: &PublicKeyPaillierPrecomputed<P>) -> Self {
        RandomizerMod::random(rng, pk).retrieve()
    }

    pub fn to_mod(&self, pk: &PublicKeyPaillierPrecomputed<P>) -> RandomizerMod<P> {
        RandomizerMod(self.0.to_mod(pk.precomputed_modulus()))
    }

    pub fn secret_box(self) -> SecretBox<Randomizer<P>> {
        Box::new(self).into()
    }
}

impl<P: PaillierParams + Zeroize> CloneableSecret for Randomizer<P> {}

#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop, Zeroize)]
pub(crate) struct RandomizerMod<P: PaillierParams>(P::UintMod);

impl<P: PaillierParams> RandomizerMod<P> {
    pub fn random(rng: &mut impl CryptoRngCore, pk: &PublicKeyPaillierPrecomputed<P>) -> Self {
        Self(pk.random_invertible_group_elem(rng))
    }

    pub fn retrieve(&self) -> Randomizer<P> {
        Randomizer(self.0.retrieve())
    }

    pub fn pow_signed(&self, exponent: &Signed<P::Uint>) -> Self {
        Self(self.0.pow_signed(exponent))
    }

    pub fn pow_signed_vartime(&self, exponent: &Signed<P::Uint>) -> Self {
        Self(self.0.pow_signed_vartime(exponent))
    }

    pub fn secret_box(self) -> SecretBox<RandomizerMod<P>> {
        Box::new(self).into()
    }
}

impl<'a, P: PaillierParams> Mul<&'a RandomizerMod<P>> for &'a RandomizerMod<P> {
    type Output = RandomizerMod<P>;
    fn mul(self, rhs: &RandomizerMod<P>) -> Self::Output {
        RandomizerMod(self.0 * rhs.0)
    }
}

impl<'a, P: PaillierParams> Mul<RandomizerMod<P>> for &'a RandomizerMod<P> {
    type Output = RandomizerMod<P>;
    fn mul(self, rhs: RandomizerMod<P>) -> Self::Output {
        self * &rhs
    }
}

impl<'a, P: PaillierParams> Mul<&'a RandomizerMod<P>> for RandomizerMod<P> {
    type Output = RandomizerMod<P>;
    fn mul(self, rhs: &RandomizerMod<P>) -> Self::Output {
        &self * rhs
    }
}

impl<P: PaillierParams> Mul<RandomizerMod<P>> for RandomizerMod<P> {
    type Output = RandomizerMod<P>;
    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl<P: PaillierParams> AsRef<P::UintMod> for RandomizerMod<P> {
    fn as_ref(&self) -> &P::UintMod {
        &self.0
    }
}

/// Paillier ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Ciphertext<P: PaillierParams> {
    ciphertext: P::WideUint,
    phantom: PhantomData<P>,
}

impl<P: PaillierParams> Ciphertext<P> {
    pub fn to_mod(&self, pk: &PublicKeyPaillierPrecomputed<P>) -> CiphertextMod<P> {
        CiphertextMod {
            pk: pk.clone(),
            ciphertext: self.ciphertext.to_mod(pk.precomputed_modulus_squared()),
        }
    }
}

/// Paillier ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CiphertextMod<P: PaillierParams> {
    pk: PublicKeyPaillierPrecomputed<P>,
    ciphertext: P::WideUintMod,
}

impl<P: PaillierParams> CiphertextMod<P> {
    pub fn public_key(&self) -> &PublicKeyPaillierPrecomputed<P> {
        &self.pk
    }

    /// Encrypts the plaintext with the provided randomizer.
    fn new_with_randomizer_inner(
        pk: &PublicKeyPaillierPrecomputed<P>,
        abs_plaintext: &P::Uint,
        randomizer: SecretBox<Randomizer<P>>,
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
        let mut prod_mod = prod.to_mod(pk.precomputed_modulus_squared());
        prod_mod.conditional_negate(plaintext_is_negative);

        let factor1 = prod_mod + P::WideUintMod::one(pk.precomputed_modulus_squared());

        let randomizer = randomizer.expose_secret().0.into_wide();
        let factor2 = randomizer
            .to_mod(pk.precomputed_modulus_squared())
            .pow_bounded(&pk.modulus_bounded().into_wide());

        let ciphertext = factor1 * factor2;

        Self {
            pk: pk.clone(),
            ciphertext,
        }
    }

    /// Encrypts the plaintext with the provided randomizer.
    pub fn new_with_randomizer(
        pk: &PublicKeyPaillierPrecomputed<P>,
        plaintext: &P::Uint,
        randomizer: SecretBox<Randomizer<P>>,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, plaintext, randomizer, Choice::from(0))
    }

    pub fn new_with_randomizer_signed(
        pk: &PublicKeyPaillierPrecomputed<P>,
        plaintext: &Signed<P::Uint>,
        randomizer: SecretBox<Randomizer<P>>,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, &plaintext.abs(), randomizer, plaintext.is_negative())
    }

    pub fn new_with_randomizer_wide(
        pk: &PublicKeyPaillierPrecomputed<P>,
        plaintext: &Signed<P::WideUint>,
        randomizer: SecretBox<Randomizer<P>>,
    ) -> Self {
        let plaintext_reduced = P::Uint::try_from_wide(
            plaintext.abs() % NonZero::new(pk.modulus().into_wide()).unwrap(),
        )
        .unwrap();
        Self::new_with_randomizer_inner(pk, &plaintext_reduced, randomizer, plaintext.is_negative())
    }

    /// Encrypts the plaintext with a random randomizer.
    pub fn new(
        rng: &mut impl CryptoRngCore,
        pk: &PublicKeyPaillierPrecomputed<P>,
        plaintext: &P::Uint,
    ) -> Self {
        Self::new_with_randomizer(pk, plaintext, Randomizer::random(rng, pk).secret_box())
    }

    #[cfg(test)]
    pub fn new_signed(
        rng: &mut impl CryptoRngCore,
        pk: &PublicKeyPaillierPrecomputed<P>,
        plaintext: &Signed<P::Uint>,
    ) -> Self {
        Self::new_with_randomizer_signed(pk, plaintext, Randomizer::random(rng, pk).secret_box())
    }

    /// Decrypts this ciphertext assuming that the plaintext is in range `[0, N)`.
    pub fn decrypt(&self, sk: &SecretKeyPaillierPrecomputed<P>) -> P::Uint {
        assert_eq!(sk.public_key(), &self.pk);

        let pk = sk.public_key();
        let totient_wide = sk.totient().into_wide();
        let modulus_wide = NonZero::new(pk.modulus().into_wide()).unwrap();

        // Calculate the plaintext `m = ((C^phi mod N^2 - 1) / N) * mu mod N`,
        // where `m` is the plaintext, `C` is the ciphertext,
        // `N` is the Paillier composite modulus,
        // `phi` is the Euler totient of `N`, and `mu = phi^(-1) mod N`.

        // `C^phi mod N^2` may be 0 if `C == N`, which is very unlikely for large `N`.
        let x = P::Uint::try_from_wide(
            (self.ciphertext.pow_bounded(&totient_wide)
                - P::WideUintMod::one(pk.precomputed_modulus_squared()))
            .retrieve()
                / modulus_wide,
        )
        .unwrap();
        let x_mod = x.to_mod(pk.precomputed_modulus());

        (x_mod * sk.inv_totient()).retrieve()
    }

    /// Decrypts this ciphertext assuming that the plaintext is in range `[-N/2, N/2)`.
    pub fn decrypt_signed(&self, sk: &SecretKeyPaillierPrecomputed<P>) -> Signed<P::Uint> {
        assert_eq!(sk.public_key(), &self.pk);

        let pk = sk.public_key();
        let positive_result = self.decrypt(sk);
        let negative_result = pk.modulus().wrapping_sub(&positive_result);
        let is_negative = Choice::from((positive_result > pk.modulus().shr_vartime(1)) as u8);

        let mut result = Signed::new_from_unsigned(
            P::Uint::conditional_select(&positive_result, &negative_result, is_negative),
            P::MODULUS_BITS as u32 - 1,
        )
        .unwrap();

        result.conditional_negate(is_negative);
        result
    }

    /// Derive the randomizer used to create this ciphertext.
    pub fn derive_randomizer(&self, sk: &SecretKeyPaillierPrecomputed<P>) -> RandomizerMod<P> {
        assert_eq!(sk.public_key(), &self.pk);

        let pk = sk.public_key();
        let modulus_wide = NonZero::new(pk.modulus().into_wide()).unwrap();

        // NOTE: the paper has a more complicated formula, but this one works just as well.

        // Remember that the ciphertext
        //     C = (N + 1)^m * rho^N mod N^2
        //     = (1 + m * N) * rho^N mod N^2`,
        //     = rho^N + m * N * rho^N + k * N^2,
        // where `k` is some integer.
        // Therefore `C mod N = rho^N mod N`.
        let ciphertext_mod_n =
            P::Uint::try_from_wide(self.ciphertext.retrieve() % modulus_wide).unwrap();
        let ciphertext_mod_n = ciphertext_mod_n.to_mod(pk.precomputed_modulus());

        // To isolate `rho`, calculate `(rho^N)^(N^(-1)) mod N`.
        // The order of `Z_N` is `phi(N)`, so the inversion in the exponent is modulo `phi(N)`.
        RandomizerMod(ciphertext_mod_n.pow_bounded(sk.inv_modulus()))
    }

    // Note: while it is true that `enc(x) (*) rhs == enc((x * rhs) mod N)`,
    // reducing the signed `rhs` modulo `N` will result in a ciphertext with a different randomizer
    // compared to what we would get if we used the signed `rhs` faithfully in the original formula.
    // So if we want to replicate the Paillier encryption manually and get the same ciphertext
    // (e.g. in the P_enc sigma-protocol), we need to process the sign correctly.
    fn homomorphic_mul(self, rhs: &Signed<P::Uint>) -> Self {
        Self {
            pk: self.pk,
            ciphertext: self.ciphertext.pow_signed(&rhs.into_wide()),
        }
    }

    fn homomorphic_mul_ref(&self, rhs: &Signed<P::Uint>) -> Self {
        Self {
            pk: self.pk.clone(),
            ciphertext: self.ciphertext.pow_signed(&rhs.into_wide()),
        }
    }

    pub fn homomorphic_mul_wide(&self, rhs: &Signed<P::WideUint>) -> Self {
        // Unfortunately we cannot implement `Mul` for `Signed<P::Uint>` and `Signed<P::WideUint>`
        // at the same time, since they can be the same type.
        // But this method is only used once, so it's not a problem to spell it out.
        Self {
            pk: self.pk.clone(),
            ciphertext: self.ciphertext.pow_signed(rhs),
        }
    }

    fn homomorphic_mul_unsigned(self, rhs: &Bounded<P::Uint>) -> Self {
        Self {
            pk: self.pk,
            ciphertext: self.ciphertext.pow_bounded(&rhs.into_wide()),
        }
    }

    fn homomorphic_mul_unsigned_ref(&self, rhs: &Bounded<P::Uint>) -> Self {
        Self {
            pk: self.pk.clone(),
            ciphertext: self.ciphertext.pow_bounded(&rhs.into_wide()),
        }
    }

    fn homomorphic_add(self, rhs: &Self) -> Self {
        assert!(self.pk == rhs.pk);
        Self {
            pk: self.pk,
            ciphertext: self.ciphertext * rhs.ciphertext,
        }
    }

    pub fn mul_randomizer(self, randomizer: &Randomizer<P>) -> Self {
        let randomizer_mod = randomizer
            .0
            .into_wide()
            .to_mod(self.pk.precomputed_modulus_squared());
        let ciphertext =
            self.ciphertext * randomizer_mod.pow_bounded(&self.pk.modulus_bounded().into_wide());
        Self {
            pk: self.pk,
            ciphertext,
        }
    }

    pub fn retrieve(&self) -> Ciphertext<P> {
        Ciphertext {
            ciphertext: self.ciphertext.retrieve(),
            phantom: PhantomData,
        }
    }
}

impl<P: PaillierParams> Add for CiphertextMod<P> {
    type Output = CiphertextMod<P>;
    fn add(self, other: CiphertextMod<P>) -> CiphertextMod<P> {
        self + &other
    }
}

impl<P: PaillierParams> Add<&CiphertextMod<P>> for CiphertextMod<P> {
    type Output = CiphertextMod<P>;
    fn add(self, other: &CiphertextMod<P>) -> CiphertextMod<P> {
        self.homomorphic_add(other)
    }
}

impl<P: PaillierParams> Mul<Signed<P::Uint>> for CiphertextMod<P> {
    type Output = CiphertextMod<P>;
    fn mul(self, other: Signed<P::Uint>) -> CiphertextMod<P> {
        self.homomorphic_mul(&other)
    }
}

impl<P: PaillierParams> Mul<Signed<P::Uint>> for &CiphertextMod<P> {
    type Output = CiphertextMod<P>;
    fn mul(self, other: Signed<P::Uint>) -> CiphertextMod<P> {
        self.homomorphic_mul_ref(&other)
    }
}

impl<P: PaillierParams> Mul<Bounded<P::Uint>> for CiphertextMod<P> {
    type Output = CiphertextMod<P>;
    fn mul(self, other: Bounded<P::Uint>) -> CiphertextMod<P> {
        self.homomorphic_mul_unsigned(&other)
    }
}

impl<P: PaillierParams> Mul<Bounded<P::Uint>> for &CiphertextMod<P> {
    type Output = CiphertextMod<P>;
    fn mul(self, other: Bounded<P::Uint>) -> CiphertextMod<P> {
        self.homomorphic_mul_unsigned_ref(&other)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::super::params::PaillierTest;
    use super::super::{PaillierParams, SecretKeyPaillier};
    use super::{CiphertextMod, RandomizerMod};

    use crate::uint::{
        subtle::ConditionallyNegatable, HasWide, NonZero, RandomMod, Signed, UintLike,
    };

    fn mul_mod<T>(lhs: &T, rhs: &Signed<T>, modulus: &NonZero<T>) -> T
    where
        T: UintLike + HasWide,
    {
        // There may be more efficient ways to do this (e.g. Barrett reduction),
        // but it's only used in tests.

        // Note that modulus here may be even, so we can't use Montgomery representation

        let wide_product = lhs.mul_wide(&rhs.abs());
        let wide_modulus = modulus.as_ref().into_wide();
        let result = T::try_from_wide(wide_product % NonZero::new(wide_modulus).unwrap()).unwrap();
        if rhs.is_negative().into() {
            modulus.as_ref().checked_sub(&result).unwrap()
        } else {
            result
        }
    }

    fn reduce<P: PaillierParams>(
        val: &Signed<P::Uint>,
        modulus: &NonZero<P::Uint>,
    ) -> Signed<P::Uint> {
        let result = val.abs() % *modulus;
        let twos_complement_result = if result > modulus.as_ref().shr_vartime(1) {
            result.wrapping_sub(modulus.as_ref())
        } else {
            result
        };
        let mut signed_result =
            Signed::new_from_unsigned(twos_complement_result, P::MODULUS_BITS as u32 - 1).unwrap();
        signed_result.conditional_negate(val.is_negative());
        signed_result
    }

    #[test]
    fn roundtrip() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();
        let plaintext =
            <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero());
        let ciphertext = CiphertextMod::<PaillierTest>::new(&mut OsRng, pk, &plaintext);
        let plaintext_back = ciphertext.decrypt(&sk);
        assert_eq!(plaintext, plaintext_back);

        let ciphertext_wire = ciphertext.retrieve();
        let ciphertext_back = ciphertext_wire.to_mod(pk);
        assert_eq!(ciphertext, ciphertext_back);
    }

    #[test]
    fn signed_roundtrip() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();
        let plaintext = Signed::random(&mut OsRng);
        let ciphertext = CiphertextMod::new_signed(&mut OsRng, pk, &plaintext);
        let plaintext_back = ciphertext.decrypt_signed(&sk);
        let plaintext_reduced = reduce::<PaillierTest>(&plaintext, &pk.modulus_nonzero());
        assert_eq!(plaintext_reduced, plaintext_back);
    }

    #[test]
    fn derive_randomizer() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();
        let plaintext =
            <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero());
        let randomizer = RandomizerMod::random(&mut OsRng, pk);
        let ciphertext = CiphertextMod::<PaillierTest>::new_with_randomizer(
            pk,
            &plaintext,
            randomizer.retrieve().secret_box(),
        );
        let randomizer_back = ciphertext.derive_randomizer(&sk);
        assert_eq!(randomizer, randomizer_back);
    }

    #[test]
    fn homomorphic_mul() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();
        let plaintext =
            <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero());
        let ciphertext = CiphertextMod::<PaillierTest>::new(&mut OsRng, pk, &plaintext);

        let coeff = Signed::random(&mut OsRng);
        let new_ciphertext = ciphertext * coeff;
        let new_plaintext = new_ciphertext.decrypt(&sk);

        assert_eq!(
            mul_mod(&plaintext, &coeff, &pk.modulus_nonzero()),
            new_plaintext
        );
    }

    #[test]
    fn homomorphic_add() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let plaintext1 =
            <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero());
        let ciphertext1 = CiphertextMod::<PaillierTest>::new(&mut OsRng, pk, &plaintext1);

        let plaintext2 =
            <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero());
        let ciphertext2 = CiphertextMod::<PaillierTest>::new(&mut OsRng, pk, &plaintext2);

        let new_ciphertext = ciphertext1 + ciphertext2;
        let new_plaintext = new_ciphertext.decrypt(&sk);

        assert_eq!(plaintext1.add_mod(&plaintext2, pk.modulus()), new_plaintext);
    }

    #[test]
    fn affine_transform() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let plaintext1 =
            <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero());
        let plaintext2 = Signed::random(&mut OsRng);
        let plaintext3 =
            <PaillierTest as PaillierParams>::Uint::random_mod(&mut OsRng, &pk.modulus_nonzero());

        let ciphertext1 = CiphertextMod::<PaillierTest>::new(&mut OsRng, pk, &plaintext1);
        let ciphertext3 = CiphertextMod::<PaillierTest>::new(&mut OsRng, pk, &plaintext3);
        let result = ciphertext1 * plaintext2 + ciphertext3;

        let plaintext_back = result.decrypt(&sk);
        assert_eq!(
            mul_mod(&plaintext1, &plaintext2, &pk.modulus_nonzero())
                .add_mod(&plaintext3, pk.modulus()),
            plaintext_back
        );
    }
}
