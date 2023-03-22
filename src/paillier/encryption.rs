use core::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::keys::{PublicKeyPaillier, SecretKeyPaillier};
use super::params::PaillierParams;
use super::uint::{
    CheckedAdd, CheckedSub, FromScalar, HasWide, Integer, Invert, NonZero, Pow, Retrieve,
    UintModLike,
};
use crate::tools::group::Scalar;

/// Paillier ciphertext.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ciphertext<P: PaillierParams> {
    ciphertext: P::QuadUint,
    phantom: PhantomData<P>,
}

impl<P: PaillierParams> Ciphertext<P> {
    /// Creates a suitable randomizer for encryption.
    fn randomizer(
        rng: &mut (impl RngCore + CryptoRng),
        pk: &PublicKeyPaillier<P>,
    ) -> P::DoubleUint {
        pk.random_invertible_group_elem(rng).retrieve()
    }

    /// Encrypts the plaintext with the provided randomizer.
    pub fn new_with_randomizer(
        pk: &PublicKeyPaillier<P>,
        plaintext: &Scalar,
        randomzier: &P::DoubleUint,
    ) -> Self {
        // `N` as a quad uint
        let modulus_quad = pk.modulus_raw().into_wide();

        // `N^2` as a quad uint
        let modulus_squared = NonZero::new(pk.modulus_raw().square_wide()).unwrap();

        let randomizer = randomzier.into_wide();
        let plaintext_uint = P::DoubleUint::from_scalar(plaintext);

        // Calculate the ciphertext `C = (N + 1)^m * rho^N mod N^2`
        // where `N` is the Paillier composite modulus, `m` is the plaintext,
        // and `rho` is the randomizer.

        // Simplify `(N + 1)^m mod N^2 == 1 + m * N mod N^2`.
        // Also the sum will never overflow since `m < N`.
        let factor1 = plaintext_uint
            .mul_wide(&pk.modulus_raw())
            .checked_add(&P::QuadUint::ONE)
            .unwrap();
        let factor1 = P::QuadUintMod::new(&factor1, &modulus_squared);

        // TODO: `modulus_quad` is bounded, use `pow_bounded_exp()`
        let factor2 = P::QuadUintMod::new(&randomizer, &modulus_squared).pow(&modulus_quad);

        let ciphertext = (factor1 * factor2).retrieve();

        Self {
            ciphertext,
            phantom: PhantomData,
        }
    }

    /// Encrypts the plaintext with a random randomizer.
    pub fn new(
        rng: &mut (impl RngCore + CryptoRng),
        pk: &PublicKeyPaillier<P>,
        plaintext: &Scalar,
    ) -> Self {
        // TODO: use an explicit RNG parameter
        // TODO: this is an ephemeral secret, use a SecretBox
        let randomizer = Self::randomizer(rng, pk);
        Self::new_with_randomizer(pk, plaintext, &randomizer)
    }

    /// Attempts to decrypt this ciphertext.
    pub fn decrypt(&self, sk: &SecretKeyPaillier<P>) -> Option<Scalar> {
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

        let plaintext_uint = (x_mod * mu).retrieve();
        plaintext_uint.try_to_scalar()
    }

    /// Derive the randomizer used to create this ciphertext.
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
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::Ciphertext;
    use crate::paillier::keys::SecretKeyPaillier;
    use crate::paillier::params::PaillierTest;
    use crate::tools::group::Scalar;

    #[test]
    fn roundtrip() {
        let plaintext = Scalar::random(&mut OsRng);
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();
        let ciphertext = Ciphertext::<PaillierTest>::new(&mut OsRng, &pk, &plaintext);
        let plaintext_back = ciphertext.decrypt(&sk).unwrap();
        assert_eq!(plaintext, plaintext_back);
    }

    #[test]
    fn derive_randomizer() {
        let plaintext = Scalar::random(&mut OsRng);
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();
        let randomizer = Ciphertext::<PaillierTest>::randomizer(&mut OsRng, &pk);
        let ciphertext =
            Ciphertext::<PaillierTest>::new_with_randomizer(&pk, &plaintext, &randomizer);
        let randomizer_back = ciphertext.derive_randomizer(&sk);
        assert_eq!(randomizer, randomizer_back);
    }
}
