use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::keys::{PublicKeyPaillierPrecomputed, SecretKeyPaillierPrecomputed};
use super::params::PaillierParams;
use crate::tools::hashing::{Chain, Hashable};
use crate::uint::{
    subtle::{Choice, ConditionallyNegatable, ConditionallySelectable},
    HasWide, NonZero, PowBoundedExp, Retrieve, Signed, UintLike, UintModLike,
};

/// Paillier ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Ciphertext<P: PaillierParams> {
    // TODO: should we have CiphertextMod, to streamline multiple operations on the ciphertext?
    // How much performance will that gain us?
    ciphertext: P::QuadUint,
    phantom: PhantomData<P>,
}

impl<P: PaillierParams> Ciphertext<P> {
    /// Creates a suitable randomizer for encryption.
    pub fn randomizer(
        rng: &mut impl CryptoRngCore,
        pk: &PublicKeyPaillierPrecomputed<P>,
    ) -> P::DoubleUint {
        pk.random_invertible_group_elem(rng).retrieve()
    }

    /// Encrypts the plaintext with the provided randomizer.
    fn new_with_randomizer_inner(
        pk: &PublicKeyPaillierPrecomputed<P>,
        abs_plaintext: &P::DoubleUint,
        randomzier: &P::DoubleUint,
        plaintext_is_negative: Choice,
    ) -> Self {
        // TODO: check that `abs_plaintext` is in range (< N)

        // `N` as a quad uint
        let modulus_quad = pk.modulus().into_wide();

        let randomizer = randomzier.into_wide();

        // Calculate the ciphertext `C = (N + 1)^m * rho^N mod N^2`
        // where `N` is the Paillier composite modulus, `m` is the plaintext,
        // and `rho` is the randomizer.

        // Simplify `(N + 1)^m mod N^2 == 1 + m * N mod N^2`.
        // Since `m` can be negative, we calculate `m * N +- 1` (never overflows since `m < N`),
        // then conditionally negate modulo N^2
        let prod = abs_plaintext.mul_wide(pk.modulus());
        let mut prod_mod = P::QuadUintMod::new(&prod, pk.precomputed_modulus_squared());
        prod_mod.conditional_negate(plaintext_is_negative);

        let factor1 = prod_mod + P::QuadUintMod::one(pk.precomputed_modulus_squared());

        let factor2 = P::QuadUintMod::new(&randomizer, pk.precomputed_modulus_squared())
            .pow_bounded_exp(&modulus_quad, P::MODULUS_BITS);

        let ciphertext = (factor1 * factor2).retrieve();

        Self {
            ciphertext,
            phantom: PhantomData,
        }
    }

    /// Encrypts the plaintext with the provided randomizer.
    pub fn new_with_randomizer(
        pk: &PublicKeyPaillierPrecomputed<P>,
        plaintext: &P::DoubleUint,
        randomzier: &P::DoubleUint,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, plaintext, randomzier, Choice::from(0))
    }

    pub fn new_with_randomizer_signed(
        pk: &PublicKeyPaillierPrecomputed<P>,
        plaintext: &Signed<P::DoubleUint>,
        randomzier: &P::DoubleUint,
    ) -> Self {
        Self::new_with_randomizer_inner(pk, &plaintext.abs(), randomzier, plaintext.is_negative())
    }

    /// Encrypts the plaintext with a random randomizer.
    pub fn new(
        rng: &mut impl CryptoRngCore,
        pk: &PublicKeyPaillierPrecomputed<P>,
        plaintext: &P::DoubleUint,
    ) -> Self {
        // TODO: use an explicit RNG parameter
        // TODO: this is an ephemeral secret, use a SecretBox
        let randomizer = Self::randomizer(rng, pk);
        Self::new_with_randomizer(pk, plaintext, &randomizer)
    }

    #[cfg(test)]
    pub fn new_signed(
        rng: &mut impl CryptoRngCore,
        pk: &PublicKeyPaillierPrecomputed<P>,
        plaintext: &Signed<P::DoubleUint>,
    ) -> Self {
        // TODO: use an explicit RNG parameter
        // TODO: this is an ephemeral secret, use a SecretBox
        let randomizer = Self::randomizer(rng, pk);
        Self::new_with_randomizer_signed(pk, plaintext, &randomizer)
    }

    /// Decrypts this ciphertext assuming that the plaintext is in range `[0, N)`.
    pub fn decrypt(&self, sk: &SecretKeyPaillierPrecomputed<P>) -> P::DoubleUint {
        let pk = sk.public_key();
        let totient_quad = NonZero::new(sk.totient().into_wide()).unwrap();
        let modulus_quad = NonZero::new(pk.modulus().into_wide()).unwrap();

        // Calculate the plaintext `m = ((C^phi mod N^2 - 1) / N) * mu mod N`,
        // where `m` is the plaintext, `C` is the ciphertext,
        // `N` is the Paillier composite modulus,
        // `phi` is the Euler totient of `N`, and `mu = phi^(-1) mod N`.

        let ciphertext_mod =
            P::QuadUintMod::new(&self.ciphertext, pk.precomputed_modulus_squared());

        // `C^phi mod N^2` may be 0 if `C == N`, which is very unlikely for large `N`.
        let x = P::DoubleUint::try_from_wide(
            (ciphertext_mod.pow_bounded_exp(&totient_quad, P::MODULUS_BITS)
                - P::QuadUintMod::one(pk.precomputed_modulus_squared()))
            .retrieve()
                / modulus_quad,
        )
        .unwrap();
        let x_mod = P::DoubleUintMod::new(&x, pk.precomputed_modulus());

        (x_mod * sk.inv_totient()).retrieve()
    }

    /// Decrypts this ciphertext assuming that the plaintext is in range `[-N/2, N/2)`.
    pub fn decrypt_signed(&self, sk: &SecretKeyPaillierPrecomputed<P>) -> Signed<P::DoubleUint> {
        let pk = sk.public_key();
        let positive_result = self.decrypt(sk);
        let negative_result = pk.modulus().wrapping_sub(&positive_result);
        let is_negative = Choice::from((positive_result > pk.modulus().shr_vartime(1)) as u8);

        let mut result = Signed::new_from_unsigned(
            P::DoubleUint::conditional_select(&positive_result, &negative_result, is_negative),
            P::MODULUS_BITS as u32 - 1,
        )
        .unwrap();

        result.conditional_negate(is_negative);
        result
    }

    /// Derive the randomizer used to create this ciphertext.
    #[allow(dead_code)] // TODO: to be used to create an error report on bad decryption
    pub fn derive_randomizer(&self, sk: &SecretKeyPaillierPrecomputed<P>) -> P::DoubleUint {
        let pk = sk.public_key();
        let modulus_quad = NonZero::new(pk.modulus().into_wide()).unwrap();

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
        let ciphertext_mod_n = P::DoubleUintMod::new(&ciphertext_mod_n, pk.precomputed_modulus());

        // To isolate `rho`, calculate `(rho^N)^(N^(-1)) mod N`.
        // The order of `Z_N` is `phi(N)`, so the inversion in the exponent is modulo `phi(N)`.
        ciphertext_mod_n
            .pow_bounded_exp(sk.inv_modulus(), P::MODULUS_BITS)
            .retrieve()
    }

    // Note: while it is true that `enc(x) (*) rhs == enc((x * rhs) mod N)`,
    // reducing the signed `rhs` modulo `N` will result in a ciphertext with a different randomizer
    // compared to what we would get if we used the signed `rhs` faithfully in the original formula.
    // So if we want to replicate the Paillier encryption manually and get the same ciphertext
    // (e.g. in the P_enc sigma-protocol), we need to process the sign correctly.
    pub fn homomorphic_mul(
        &self,
        pk: &PublicKeyPaillierPrecomputed<P>,
        rhs: &Signed<P::DoubleUint>,
    ) -> Self {
        let ciphertext_mod =
            P::QuadUintMod::new(&self.ciphertext, pk.precomputed_modulus_squared());
        // This will not panic as long as the randomizer was chosen to be invertible.
        let ciphertext = ciphertext_mod.pow_signed(&rhs.into_wide()).retrieve();
        Self {
            ciphertext,
            phantom: PhantomData,
        }
    }

    pub fn homomorphic_add(&self, pk: &PublicKeyPaillierPrecomputed<P>, rhs: &Self) -> Self {
        let lhs_mod = P::QuadUintMod::new(&self.ciphertext, pk.precomputed_modulus_squared());
        let rhs_mod = P::QuadUintMod::new(&rhs.ciphertext, pk.precomputed_modulus_squared());
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
    use crate::uint::{
        subtle::ConditionallyNegatable, HasWide, NonZero, RandomMod, Signed, UintLike,
    };

    fn mul_mod<T>(lhs: &T, rhs: &Signed<T>, modulus: &NonZero<T>) -> T
    where
        T: UintLike + HasWide,
    {
        // TODO: move to crypto-bigint, and make more efficient (e.g. Barrett reduction)
        // CHECK: check the constraints on rhs: do we need rhs < modulus,
        // or will it be reduced all the same?
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
        val: &Signed<P::DoubleUint>,
        modulus: &NonZero<P::DoubleUint>,
    ) -> Signed<P::DoubleUint> {
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
        let plaintext = <PaillierTest as PaillierParams>::DoubleUint::random_mod(
            &mut OsRng,
            &pk.modulus_nonzero(),
        );
        let ciphertext = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext);
        let plaintext_back = ciphertext.decrypt(&sk);
        assert_eq!(plaintext, plaintext_back);
    }

    #[test]
    fn signed_roundtrip() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();
        let plaintext = Signed::random(&mut OsRng);
        let ciphertext = Ciphertext::new_signed(&mut OsRng, pk, &plaintext);
        let plaintext_back = ciphertext.decrypt_signed(&sk);
        let plaintext_reduced = reduce::<PaillierTest>(&plaintext, &pk.modulus_nonzero());
        assert_eq!(plaintext_reduced, plaintext_back);
    }

    #[test]
    fn derive_randomizer() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();
        let plaintext = <PaillierTest as PaillierParams>::DoubleUint::random_mod(
            &mut OsRng,
            &pk.modulus_nonzero(),
        );
        let randomizer = Ciphertext::<PaillierTest>::randomizer(&mut OsRng, pk);
        let ciphertext =
            Ciphertext::<PaillierTest>::new_with_randomizer(pk, &plaintext, &randomizer);
        let randomizer_back = ciphertext.derive_randomizer(&sk);
        assert_eq!(randomizer, randomizer_back);
    }

    #[test]
    fn homomorphic_mul() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();
        let plaintext = <PaillierTest as PaillierParams>::DoubleUint::random_mod(
            &mut OsRng,
            &pk.modulus_nonzero(),
        );
        let ciphertext = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext);

        let coeff = Signed::random(&mut OsRng);
        let new_ciphertext = ciphertext.homomorphic_mul(pk, &coeff);
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

        let plaintext1 = <PaillierTest as PaillierParams>::DoubleUint::random_mod(
            &mut OsRng,
            &pk.modulus_nonzero(),
        );
        let ciphertext1 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext1);

        let plaintext2 = <PaillierTest as PaillierParams>::DoubleUint::random_mod(
            &mut OsRng,
            &pk.modulus_nonzero(),
        );
        let ciphertext2 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext2);

        let new_ciphertext = ciphertext1.homomorphic_add(pk, &ciphertext2);
        let new_plaintext = new_ciphertext.decrypt(&sk);

        assert_eq!(plaintext1.add_mod(&plaintext2, pk.modulus()), new_plaintext);
    }

    #[test]
    fn affine_transform() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let plaintext1 = <PaillierTest as PaillierParams>::DoubleUint::random_mod(
            &mut OsRng,
            &pk.modulus_nonzero(),
        );
        let plaintext2 = Signed::random(&mut OsRng);
        let plaintext3 = <PaillierTest as PaillierParams>::DoubleUint::random_mod(
            &mut OsRng,
            &pk.modulus_nonzero(),
        );

        let ciphertext1 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext1);
        let ciphertext3 = Ciphertext::<PaillierTest>::new(&mut OsRng, pk, &plaintext3);
        let result = ciphertext1
            .homomorphic_mul(pk, &plaintext2)
            .homomorphic_add(pk, &ciphertext3);

        let plaintext_back = result.decrypt(&sk);
        assert_eq!(
            mul_mod(&plaintext1, &plaintext2, &pk.modulus_nonzero())
                .add_mod(&plaintext3, pk.modulus()),
            plaintext_back
        );
    }
}
