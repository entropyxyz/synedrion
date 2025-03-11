use alloc::vec::Vec;

use bip32::{ChainCode, DerivationPath, PrivateKeyBytes, PublicKey as _};
use digest::Digest;
use ecdsa::{hazmat::DigestPrimitive, VerifyingKey};
use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, PrimeCurve,
};

/// Used for deriving child keys from a parent type.
pub trait DeriveChildKey<C: CurveArithmetic + PrimeCurve>: Sized {
    /// Return a verifying key derived from the given type using the BIP-32 scheme.
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey<C>, bip32::Error>;
}

/// Trait for types that can derive BIP32 style "tweaks" from public keys.
pub trait PublicTweakable {
    /// The public key type implementing [`bip32::PublicKey`].
    type Bip32Pk: bip32::PublicKey + Clone;
    /// Convert `self` into something that can be used for BIP32 derivation.
    fn tweakable_pk(&self) -> Self::Bip32Pk;
    /// Convert a BIP32 public key back into the original type. For "real" BIP32 compatible curves
    /// such as secp256k1, this is just a clone.
    fn key_from_tweakable_pk(pk: &Self::Bip32Pk) -> Self;
}

/// Trait for types that can derive BIP32 style "tweaks" from secret keys.
pub trait SecretTweakable {
    /// The private key type implementing [`bip32::PrivateKey`].
    type Bip32Sk: bip32::PrivateKey + Clone;
    /// Convert `self` into something that can be used for BIP32 derivation.
    fn tweakable_sk(&self) -> Self::Bip32Sk;
    /// Convert the BIP32-supporting private key into `self`.
    fn key_from_tweakable_sk(pk: &Self::Bip32Sk) -> Self;
}

impl<C> DeriveChildKey<C> for VerifyingKey<C>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
    VerifyingKey<C>: PublicTweakable,
{
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey<C>, bip32::Error> {
        let tweakable = self.tweakable_pk();
        let tweaks = derive_tweaks::<C>(&tweakable, derivation_path)?;
        apply_tweaks_public(self, &tweaks)
    }
}

pub(crate) fn derive_tweaks<C>(
    public_key: &(impl bip32::PublicKey + Clone),
    derivation_path: &DerivationPath,
) -> Result<Vec<PrivateKeyBytes>, bip32::Error>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let mut public_key = public_key.clone();

    // TODO(#134): deriving the initial chain code from public information. Is this okay?
    let pubkey_bytes = public_key.to_bytes();
    let initial_chain_code = <C as DigestPrimitive>::Digest::new()
        .chain_update(b"chain-code-derivation")
        .chain_update(pubkey_bytes)
        .finalize();
    let mut chain_code: ChainCode = Default::default();
    let len = initial_chain_code.len().min(chain_code.len());
    chain_code
        .get_mut(..len)
        .ok_or(bip32::Error::Decode)?
        .copy_from_slice(initial_chain_code.get(..len).ok_or(bip32::Error::Decode)?.as_ref());

    let mut tweaks = Vec::new();
    for child_number in derivation_path.iter() {
        let (tweak, new_chain_code) = public_key.derive_tweak(&chain_code, child_number)?;
        public_key = public_key.derive_child(tweak)?;
        tweaks.push(tweak);
        chain_code = new_chain_code;
    }

    Ok(tweaks)
}

pub(crate) fn apply_tweaks_public<C>(
    public_key: &VerifyingKey<C>,
    tweaks: &[PrivateKeyBytes],
) -> Result<VerifyingKey<C>, bip32::Error>
where
    C: CurveArithmetic + PrimeCurve,
    <C as Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    VerifyingKey<C>: PublicTweakable,
{
    let mut public_key = public_key.tweakable_pk();
    for tweak in tweaks {
        public_key = public_key.derive_child(*tweak)?;
    }
    Ok(PublicTweakable::key_from_tweakable_pk(&public_key))
}
