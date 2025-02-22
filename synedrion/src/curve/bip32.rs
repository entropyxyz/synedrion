use crate::{
    curve::{Point, Scalar},
    tools::Secret,
    ProductionParams112, SchemeParams, TestParams,
};
use alloc::vec::Vec;
use bip32::{ChainCode, DerivationPath, PrivateKey as _, PrivateKeyBytes};

use digest::typenum::Unsigned;
use digest::Digest;
use ecdsa::{hazmat::DigestPrimitive, SigningKey, VerifyingKey};
use manul::protocol::PartyId;
use primeorder::elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, PrimeCurve, PublicKey, SecretKey,
};
use tiny_curve::{PrivateKeyBip32, PublicKeyBip32};

use crate::www02::ThresholdKeyShare;

/// Used for deriving child keys from a parent type.
pub trait DeriveChildKey<C: CurveArithmetic + PrimeCurve>: Sized {
    /// Return a verifying key derived from the given type using the BIP-32 scheme.
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey<C>, bip32::Error>;
}

mod sealed {
    use super::*;
    pub trait Sealed {}
    impl Sealed for VerifyingKey<tiny_curve::TinyCurve64> {}
    impl Sealed for VerifyingKey<k256::Secp256k1> {}
    impl Sealed for SigningKey<tiny_curve::TinyCurve64> {}
    impl Sealed for SigningKey<k256::Secp256k1> {}
}

/// Trait for types that can derive BIP32 style "tweaks" from public keys.
pub trait PubTweakable: sealed::Sealed {
    fn tweakable_pk(&self) -> impl bip32::PublicKey + Clone;
}

/// Trait for types that can derive BIP32 style "tweaks" from secret keys.
pub trait SecretTweakable: sealed::Sealed {
    /// Convert `self` into something that can be used for BIP32 derivation.
    fn tweakable_sk(&self) -> impl bip32::PrivateKey + Clone;
}

impl PubTweakable for VerifyingKey<<TestParams as SchemeParams>::Curve> {
    fn tweakable_pk(&self) -> impl bip32::PublicKey + Clone {
        let pk: PublicKey<_> = self.into();
        let wrapped_pk: PublicKeyBip32<_> = pk.into();
        wrapped_pk
    }
}

impl PubTweakable for VerifyingKey<<ProductionParams112 as SchemeParams>::Curve> {
    fn tweakable_pk(&self) -> impl bip32::PublicKey + Clone {
        *self
    }
}

impl SecretTweakable for SigningKey<<TestParams as SchemeParams>::Curve> {
    fn tweakable_sk(&self) -> impl bip32::PrivateKey + Clone {
        let sk: SecretKey<_> = self.into();
        let wrapped_sk: PrivateKeyBip32<_> = sk.into();
        wrapped_sk
    }
}

impl SecretTweakable for SigningKey<<ProductionParams112 as SchemeParams>::Curve> {
    fn tweakable_sk(&self) -> impl bip32::PrivateKey + Clone {
        let sk: SecretKey<_> = self.into();
        sk
    }
}

impl<P, I> ThresholdKeyShare<P, I>
where
    P: SchemeParams,
    VerifyingKey<P::Curve>: PubTweakable,
    SigningKey<P::Curve>: SecretTweakable,
    I: PartyId,
{
    /// Deterministically derives a child share using BIP-32 standard.
    pub fn derive_bip32(&self, derivation_path: &DerivationPath) -> Result<Self, bip32::Error> {
        let pk = self.verifying_key().map_err(|_| bip32::Error::Crypto)?;
        let tweakable_pk = pk.tweakable_pk();
        let tweaks = derive_tweaks::<P::Curve>(&tweakable_pk, derivation_path)?;

        // Will fail here if secret share is zero
        let secret_share = self.secret_share.clone().to_signing_key().ok_or(bip32::Error::Crypto)?;
        let mut tweakable_sk = secret_share.tweakable_sk();
        for tweak in &tweaks {
            tweakable_sk = tweakable_sk.derive_child(*tweak)?;
        }
        let bytes = tweakable_sk.to_bytes();
        let bytes = bytes.get(32 - Scalar::<P>::repr_len()..).ok_or(bip32::Error::Decode)?;
        let secret_share = Scalar::try_from_be_bytes(bytes).map_err(|_e| bip32::Error::Decode)?;
        let secret_share = Secret::init_with(|| secret_share);

        let public_shares = self
            .public_shares
            .clone()
            .into_iter()
            .map(|(id, point)|
            // Will fail here if the final or one of the intermediate points is an identity
            point.to_verifying_key().ok_or(bip32::Error::Crypto)
                .and_then(|vkey| apply_tweaks_public(vkey.tweakable_pk(), &tweaks))
                .map(|vkey| (id, Point::from_verifying_key(&vkey))))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            owner: self.owner.clone(),
            threshold: self.threshold,
            share_ids: self.share_ids.clone(),
            secret_share,
            public_shares,
        })
    }
}

impl<P, I> DeriveChildKey<P::Curve> for ThresholdKeyShare<P, I>
where
    P: SchemeParams,
    I: PartyId,
    VerifyingKey<P::Curve>: PubTweakable,
{
    fn derive_verifying_key_bip32(
        &self,
        derivation_path: &DerivationPath,
    ) -> Result<VerifyingKey<P::Curve>, bip32::Error> {
        let public_key = self.verifying_key().map_err(|_| bip32::Error::Crypto)?;
        let tweakable_pk = public_key.tweakable_pk();
        let tweaks = derive_tweaks::<<P as SchemeParams>::Curve>(&tweakable_pk, derivation_path)?;
        apply_tweaks_public(tweakable_pk, &tweaks)
    }
}

impl<C> DeriveChildKey<C> for VerifyingKey<C>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
    VerifyingKey<C>: PubTweakable,
{
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey<C>, bip32::Error> {
        let tweakable = self.tweakable_pk();
        let tweaks = derive_tweaks::<C>(&tweakable, derivation_path)?;
        apply_tweaks_public(tweakable, &tweaks)
    }
}

fn derive_tweaks<C>(
    public_key: &(impl bip32::PublicKey + Clone),
    derivation_path: &DerivationPath,
) -> Result<Vec<PrivateKeyBytes>, bip32::Error>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let mut public_key = public_key.clone();

    // Note: deriving the initial chain code from public information. Is this okay? <–– PROBABLY NOT OK?
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

fn apply_tweaks_public<C>(
    public_key: impl bip32::PublicKey + Clone,
    tweaks: &[PrivateKeyBytes],
) -> Result<VerifyingKey<C>, bip32::Error>
where
    C: CurveArithmetic + PrimeCurve,
    <C as Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    let mut public_key = public_key;
    for tweak in tweaks {
        public_key = public_key.derive_child(*tweak)?;
    }
    let offset = bip32::KEY_SIZE - <C as Curve>::FieldBytesSize::USIZE;
    let bytes = public_key.to_bytes();
    let bytes = bytes.get(offset..).ok_or(bip32::Error::Decode)?;
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_e| bip32::Error::Decode)
}
