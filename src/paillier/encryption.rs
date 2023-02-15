use super::keys::{PublicKeyPaillier, SecretKeyPaillier};
use super::params::PaillierParams;
use crate::tools::group::Scalar;

// TODO: implement actual encryption
#[derive(Clone)]
pub struct Ciphertext<P: PaillierParams>(Scalar, PublicKeyPaillier<P>);

impl<P: PaillierParams> Ciphertext<P> {
    pub fn new(pk: &PublicKeyPaillier<P>, plaintext: &Scalar) -> Self {
        Self(plaintext.clone(), pk.clone())
    }

    pub fn decrypt(&self, sk: &SecretKeyPaillier<P>) -> Option<Scalar> {
        if sk.public_key() != self.1 {
            return None;
        }
        Some(self.0.clone())
    }
}
