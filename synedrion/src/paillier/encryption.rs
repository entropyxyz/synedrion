use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::keys::{PublicKeyPaillier, SecretKeyPaillier};
use super::params::PaillierParams;
use crate::tools::hashing::{Chain, Hashable};
use crate::uint::{
    subtle::Choice, CheckedSub, HasWide, Integer, Invert, NonZero, Pow, Retrieve, Signed,
    UintModLike,
};

/// Paillier ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ciphertext<P: PaillierParams> {
    ciphertext: P::QuadUint,
    phantom: PhantomData<P>,
}

impl<P: PaillierParams> Ciphertext<P> {
    /// Creates a suitable randomizer for encryption.
    pub(crate) fn randomizer(
        rng: &mut impl CryptoRngCore,
        pk: &PublicKeyPaillier<P>,
    ) -> P::DoubleUint {
        pk.random_invertible_group_elem(rng).retrieve()
    }

    /// Encrypts the plaintext with the provided randomizer.
    fn new_with_randomizer_inner(
        pk: &PublicKeyPaillier<P>,
        abs_plaintext: &P::DoubleUint,
        randomzier: &P::DoubleUint,
        plaintext_is_negative: Choice,
    ) -> Self {
        // TODO: check that `abs_plaintext` is in range (< N)

        // `N` as a quad uint
        let modulus_quad = pk.modulus_raw().into_wide();

        // `N^2` as a quad uint
        let modulus_squared = NonZero::new(pk.modulus_raw().square_wide()).unwrap();

        let randomizer = randomzier.into_wide();

        // Calculate the ciphertext `C = (N + 1)^m * rho^N mod N^2`
        // where `N` is the Paillier composite modulus, `m` is the plaintext,
        // and `rho` is the randomizer.

        // Simplify `(N + 1)^m mod N^2 == 1 + m * N mod N^2`.
        // Since `m` can be negative, we calculate `m * N +- 1` (never overflows since `m < N`),
        // then conditionally negate modulo N^2
        let prod = abs_plaintext.mul_wide(&pk.modulus_raw());
        let mut prod_mod = P::QuadUintMod::new(&prod, &modulus_squared);

        // TODO: use conditionally_negate() after crypto_bigint 0.5.3 is released
        if plaintext_is_negative.into() {
            prod_mod = -prod_mod;
        }

        let factor1 = prod_mod + P::QuadUintMod::one(&modulus_squared);

        // TODO: `modulus_quad` is bounded, use `pow_bounded_exp()`
        let factor2 = P::QuadUintMod::new(&randomizer, &modulus_squared).pow(&modulus_quad);

        let ciphertext = (factor1 * factor2).retrieve();

        Self {
            ciphertext,
            phantom: PhantomData,
        }
    }

    /// Encrypts the plaintext with the provided randomizer.
    pub fn new_with_randomizer(
        pk: &PublicKeyPaillier<P>,
        plaintext: &P::DoubleUint,
        randomzier: &P::DoubleUint,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, plaintext, randomzier, Choice::from(0))
    }

    pub fn new_with_randomizer_signed(
        pk: &PublicKeyPaillier<P>,
        plaintext: &Signed<P::DoubleUint>,
        randomzier: &P::DoubleUint,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, &plaintext.abs(), randomzier, plaintext.is_negative())
    }

    /// Encrypts the plaintext with a random randomizer.
    pub fn new(
        rng: &mut impl CryptoRngCore,
        pk: &PublicKeyPaillier<P>,
        plaintext: &P::DoubleUint,
    ) -> Self {
        // TODO: use an explicit RNG parameter
        // TODO: this is an ephemeral secret, use a SecretBox
        let randomizer = Self::randomizer(rng, pk);
        Self::new_with_randomizer(pk, plaintext, &randomizer)
    }

    /// Attempts to decrypt this ciphertext.
    pub fn decrypt(&self, sk: &SecretKeyPaillier<P>) -> P::DoubleUint {
        // TODO: these can be precalculated
        let pk = sk.public_key();
        let modulus_squared = NonZero::new(pk.modulus_raw().square_wide()).unwrap();
        let totient_quad = NonZero::new(sk.totient().as_ref().into_wide()).unwrap();
        let modulus_quad = NonZero::new(pk.modulus().as_ref().into_wide()).unwrap();
        let mu = P::DoubleUintMod::new(sk.totient().as_ref(), &pk.modulus())
            .invert()
            .unwrap();

        // Calculate the plaintext `m = ((C^phi mod N^2 - 1) / N) * mu mod N`,
        // where `m` is the plaintext, `C` is the ciphertext,
        // `N` is the Paillier composite modulus,
        // `phi` is the Euler totient of `N`, and `mu = phi^(-1) mod N`.

        let ciphertext_mod = P::QuadUintMod::new(&self.ciphertext, &modulus_squared);

        // TODO: subtract 1 from the `C^phi` while still in the modulo representation.
        // we need access to DynResidueParams for that.
        // `C^phi mod N^2` may be 0 if `C == N`, which is very unlikely for large `N`.
        let x = P::DoubleUint::try_from_wide(
            ciphertext_mod
                .pow(&totient_quad)
                .retrieve()
                .checked_sub(&P::QuadUint::ONE)
                .unwrap()
                / modulus_quad,
        )
        .unwrap();
        let x_mod = P::DoubleUintMod::new(&x, &pk.modulus());

        (x_mod * mu).retrieve()
    }

    /// Derive the randomizer used to create this ciphertext.
    #[allow(dead_code)] // TODO: to be used to create an error report on bad decryption
    pub fn derive_randomizer(&self, sk: &SecretKeyPaillier<P>) -> P::DoubleUint {
        let pk = sk.public_key();
        let modulus_quad = NonZero::new(pk.modulus().as_ref().into_wide()).unwrap();

        // CHECK: the paper has a more complicated formula,
        // but this one seems to work just as well.

        // Remember that the ciphertext
        //     C = (N + 1)^m * rho^N mod N^2
        //     = (1 + m * N) * rho^N mod N^2`,
        //     = rho^N + m * N * rho^N + k * N^2,
        // where `k` is some integer.
        // Therefore `C mod N = rho^N mod N`.
        let ciphertext_mod_n =
            P::DoubleUint::try_from_wide(self.ciphertext % modulus_quad).unwrap();
        let ciphertext_mod_n = P::DoubleUintMod::new(&ciphertext_mod_n, &pk.modulus());

        // To isolate `rho`, calculate `(rho^N)^(N^(-1)) mod N`.
        // The order of `Z_N` is `phi(N)`, so the inversion in the exponent is modulo `phi(N)`.
        ciphertext_mod_n.pow(&sk.inv_modulus()).retrieve()
    }

    fn homomorphic_mul_internal(
        &self,
        pk: &PublicKeyPaillier<P>,
        rhs: &P::DoubleUint,
        is_negative: Choice,
    ) -> Self {
        let modulus_squared = NonZero::new(pk.modulus_raw().square_wide()).unwrap();
        let mut ciphertext_mod = P::QuadUintMod::new(&self.ciphertext, &modulus_squared);
        let plaintext_uint = rhs.into_wide();

        // TODO: an alternative way would be to reduce the signed `rhs`
        // modulo `phi(N^2) == phi(N) * N`. Check if it is faster.
        if is_negative.into() {
            // This will not panic as long as the randomizer was chosen to be invertible.
            ciphertext_mod = ciphertext_mod.invert().unwrap()
        }

        // TODO: use pow_bounded_exp()?
        let ciphertext = ciphertext_mod.pow(&plaintext_uint).retrieve();
        Self {
            ciphertext,
            phantom: PhantomData,
        }
    }

    pub fn homomorphic_mul(&self, pk: &PublicKeyPaillier<P>, rhs: &P::DoubleUint) -> Self {
        self.homomorphic_mul_internal(pk, rhs, Choice::from(0))
    }

    // Note: while it is true that `enc(x) (*) rhs == enc((x * rhs) mod N)`,
    // reducing the signed `rhs` modulo `N` will result in a ciphertext with a different randomizer
    // compared to what we would get if we used the signed `rhs` faithfully in the original formula.
    // So if we want to replicate the Paillier encryption manually and get the same ciphertext
    // (e.g. in the P_enc sigma-protocol), we need to process the sign correctly.
    pub fn homomorphic_mul_signed(
        &self,
        pk: &PublicKeyPaillier<P>,
        rhs: &Signed<P::DoubleUint>,
    ) -> Self {
        self.homomorphic_mul_internal(pk, &rhs.abs(), rhs.is_negative())
    }

    pub fn homomorphic_add(&self, pk: &PublicKeyPaillier<P>, rhs: &Self) -> Self {
        let modulus_squared = NonZero::new(pk.modulus_raw().square_wide()).unwrap();
        let lhs_mod = P::QuadUintMod::new(&self.ciphertext, &modulus_squared);
        let rhs_mod = P::QuadUintMod::new(&rhs.ciphertext, &modulus_squared);
        Self {
            ciphertext: (lhs_mod * rhs_mod).retrieve(),
            phantom: PhantomData,
        }
    }
}

impl<P: PaillierParams> Hashable for Ciphertext<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::Ciphertext;
    use crate::paillier::{PaillierParams, PaillierTest, SecretKeyPaillier};
    use crate::uint::{HasWide, NonZero, RandomMod, UintLike};

    fn mul_mod<T>(lhs: &T, rhs: &T, modulus: &NonZero<T>) -> T
    where
        T: UintLike + HasWide,
    {
        // TODO: move to crypto-bigint, and make more efficient (e.g. Barrett reduction)
        // CHECK: check the constraints on rhs: do we need rhs < modulus,
        // or will it be reduced all the same?
        // Note that modulus here may be even, so we can't use Montgomery representation
        let wide_product = lhs.mul_wide(rhs);
        let wide_modulus = modulus.as_ref().into_wide();
        T::try_from_wide(wide_product % NonZero::new(wide_modulus).unwrap()).unwrap()
    }

    #[test]
    fn roundtrip() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();
        let plaintext =
            <PaillierTest as PaillierParams>::DoubleUint::random_mod(&mut OsRng, &pk.modulus());
        let ciphertext = Ciphertext::<PaillierTest>::new(&mut OsRng, &pk, &plaintext);
        let plaintext_back = ciphertext.decrypt(&sk);
        assert_eq!(plaintext, plaintext_back);
    }

    #[test]
    fn derive_randomizer() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();
        let plaintext =
            <PaillierTest as PaillierParams>::DoubleUint::random_mod(&mut OsRng, &pk.modulus());
        let randomizer = Ciphertext::<PaillierTest>::randomizer(&mut OsRng, &pk);
        let ciphertext =
            Ciphertext::<PaillierTest>::new_with_randomizer(&pk, &plaintext, &randomizer);
        let randomizer_back = ciphertext.derive_randomizer(&sk);
        assert_eq!(randomizer, randomizer_back);
    }

    #[test]
    fn homomorphic_mul() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();
        let plaintext =
            <PaillierTest as PaillierParams>::DoubleUint::random_mod(&mut OsRng, &pk.modulus());
        let ciphertext = Ciphertext::<PaillierTest>::new(&mut OsRng, &pk, &plaintext);

        let coeff =
            <PaillierTest as PaillierParams>::DoubleUint::random_mod(&mut OsRng, &pk.modulus());
        let new_ciphertext = ciphertext.homomorphic_mul(&pk, &coeff);
        let new_plaintext = new_ciphertext.decrypt(&sk);

        assert_eq!(mul_mod(&plaintext, &coeff, &pk.modulus()), new_plaintext);
    }

    #[test]
    fn homomorphic_add() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();

        let plaintext1 =
            <PaillierTest as PaillierParams>::DoubleUint::random_mod(&mut OsRng, &pk.modulus());
        let ciphertext1 = Ciphertext::<PaillierTest>::new(&mut OsRng, &pk, &plaintext1);

        let plaintext2 =
            <PaillierTest as PaillierParams>::DoubleUint::random_mod(&mut OsRng, &pk.modulus());
        let ciphertext2 = Ciphertext::<PaillierTest>::new(&mut OsRng, &pk, &plaintext2);

        let new_ciphertext = ciphertext1.homomorphic_add(&pk, &ciphertext2);
        let new_plaintext = new_ciphertext.decrypt(&sk);

        assert_eq!(
            plaintext1.add_mod(&plaintext2, &pk.modulus()),
            new_plaintext
        );
    }

    #[test]
    fn affine_transform() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();

        let plaintext1 =
            <PaillierTest as PaillierParams>::DoubleUint::random_mod(&mut OsRng, &pk.modulus());
        let plaintext2 =
            <PaillierTest as PaillierParams>::DoubleUint::random_mod(&mut OsRng, &pk.modulus());
        let plaintext3 =
            <PaillierTest as PaillierParams>::DoubleUint::random_mod(&mut OsRng, &pk.modulus());

        let ciphertext1 = Ciphertext::<PaillierTest>::new(&mut OsRng, &pk, &plaintext1);
        let ciphertext3 = Ciphertext::<PaillierTest>::new(&mut OsRng, &pk, &plaintext3);
        let result = ciphertext1
            .homomorphic_mul(&pk, &plaintext2)
            .homomorphic_add(&pk, &ciphertext3);

        let plaintext_back = result.decrypt(&sk);
        assert_eq!(
            mul_mod(&plaintext1, &plaintext2, &pk.modulus()).add_mod(&plaintext3, &pk.modulus()),
            plaintext_back
        );
    }
}
