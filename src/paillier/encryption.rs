use core::marker::PhantomData;
use core::ops::{Div, Rem};

use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::keys::{PublicKeyPaillier, SecretKeyPaillier};
use super::params::PaillierParams;
use super::uint::{
    CheckedAdd, CheckedSub, FromScalar, HasWide, Integer, Invert, NonZero, Pow, Retrieve,
    UintModLike,
};
use crate::tools::group::Scalar;

// TODO: implement actual encryption
#[derive(Clone, Serialize, Deserialize)]
pub struct Ciphertext<P: PaillierParams> {
    ciphertext: P::QuadUint,
    phantom: PhantomData<P>,
}

impl<P: PaillierParams> Ciphertext<P> {
    fn randomizer(
        rng: &mut (impl RngCore + CryptoRng),
        pk: &PublicKeyPaillier<P>,
    ) -> P::DoubleUint {
        pk.random_invertible_group_elem(rng).retrieve()
    }

    fn new_with_randomizer(
        pk: &PublicKeyPaillier<P>,
        plaintext: &Scalar,
        randomzier: &P::DoubleUint,
    ) -> Self {
        let randomizer = randomzier.into_wide();
        let plaintext_uint = P::DoubleUint::from_scalar(plaintext).into_wide();

        let modulus_plus_one = pk
            .modulus_raw()
            .checked_add(&P::DoubleUint::ONE)
            .unwrap()
            .into_wide();
        let modulus_squared = NonZero::new(pk.modulus_raw().square_wide()).unwrap();

        // TODO: `plaintext_uint` is bounded, use `pow_bounded_exp()`
        let factor1 = P::QuadUintMod::new(&modulus_plus_one, &modulus_squared).pow(&plaintext_uint);

        // TODO: `modulus_raw` is bounded, use `pow_bounded_exp()`
        let modulus_quad = pk.modulus_raw().into_wide();
        let factor2 = P::QuadUintMod::new(&randomizer, &modulus_squared).pow(&modulus_quad);

        let ciphertext = (factor1 * factor2).retrieve();

        Self {
            ciphertext,
            phantom: PhantomData,
        }
    }

    pub fn new(pk: &PublicKeyPaillier<P>, plaintext: &Scalar) -> Self {
        // TODO: use an explicit RNG parameter
        // TODO: this is an ephemeral secret, use a SecretBox
        let randomizer = Self::randomizer(&mut OsRng, pk);
        Self::new_with_randomizer(pk, plaintext, &randomizer)
    }

    pub fn decrypt(&self, sk: &SecretKeyPaillier<P>) -> Option<Scalar> {
        let pk = sk.public_key();
        let modulus_squared = NonZero::new(pk.modulus_raw().square_wide()).unwrap();
        let ciphertext_mod = P::QuadUintMod::new(&self.ciphertext, &modulus_squared);
        let totient_quad = NonZero::new(sk.totient().as_ref().into_wide()).unwrap();
        let modulus_quad = NonZero::new(pk.modulus().as_ref().into_wide()).unwrap();

        let x = P::DoubleUint::try_from_wide(
            ciphertext_mod
                .pow(&totient_quad)
                .retrieve()
                .checked_sub(&P::QuadUint::ONE)
                .unwrap()
                .div(modulus_quad),
        )
        .unwrap();
        let x_mod = P::DoubleUintMod::new(&x, &pk.modulus());
        let mu = P::DoubleUintMod::new(sk.totient().as_ref(), &pk.modulus())
            .invert()
            .unwrap();
        let plaintext_uint = (x_mod * mu).retrieve();
        plaintext_uint.try_to_scalar()
    }

    pub fn derive_randomizer(&self, sk: &SecretKeyPaillier<P>) -> P::DoubleUint {
        let pk = sk.public_key();
        let modulus_quad = NonZero::new(pk.modulus().as_ref().into_wide()).unwrap();

        let ciphertext_mod_n =
            P::DoubleUint::try_from_wide(self.ciphertext.rem(modulus_quad)).unwrap();
        let ciphertext_mod_n = P::DoubleUintMod::new(&ciphertext_mod_n, &pk.modulus());

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
        let ciphertext = Ciphertext::<PaillierTest>::new(&pk, &plaintext);
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
