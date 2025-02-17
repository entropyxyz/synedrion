use core::{fmt::Debug, ops::Add};

use crate::{
    curve::{Point, Scalar},
    SchemeParams,
};
use alloc::vec::Vec;
use bip32::{DerivationPath, PrivateKey as _, PrivateKeyBytes};
use digest::generic_array::ArrayLength;

use digest::Digest;
use ecdsa::{
    hazmat::{DigestPrimitive, SignPrimitive},
    SigningKey, VerifyingKey,
};
use k256::Secp256k1;
use primeorder::elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, PrimeCurve, PublicKey,
};
use serde::{Deserialize, Serialize};
use tiny_curve::{PublicKeyBip32, TinyCurve64};

use super::ThresholdKeyShare;

/// Used for deriving child keys from a parent type.
pub trait DeriveChildKey<C: CurveArithmetic + PrimeCurve> {
    /// The error type.
    type Error;
    /// Return a verifying key derived from the given type using the BIP-32 scheme.
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey<C>, Self::Error>;
}

impl<P, I> ThresholdKeyShare<P, I>
where
    P: SchemeParams,
    VerifyingKey<P::Curve>: bip32::PublicKey,
    SigningKey<P::Curve>: bip32::PrivateKey,
    I: Clone + Ord + PartialEq + Debug + Serialize + for<'x> Deserialize<'x>,
{
    /// Deterministically derives a child share using BIP-32 standard.
    pub fn derive_bip32(&self, derivation_path: &DerivationPath) -> Result<Self, bip32::Error> {
        let pk = self.verifying_key().map_err(|_| bip32::Error::Crypto)?;
        let tweaks = derive_tweaks::<P::Curve, bip32::Error>(pk, derivation_path)?;

        // Will fail here if secret share is zero
        let secret_share = self.secret_share.clone().to_signing_key().ok_or(bip32::Error::Crypto)?;
        let secret_share =
            apply_tweaks_private(secret_share, &tweaks).map(|signing_key| Scalar::from_signing_key(&signing_key))?;

        let public_shares = self
            .public_shares
            .clone()
            .into_iter()
            .map(|(id, point)|
            // Will fail here if the final or one of the intermediate points is an identity
            point.to_verifying_key().ok_or(bip32::Error::Crypto)
                .and_then(|vkey| apply_tweaks_public(vkey, &tweaks))
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
    VerifyingKey<P::Curve>: bip32::PublicKey,
    P: SchemeParams,
    I: Clone + Ord + PartialEq + Debug + Serialize + for<'x> Deserialize<'x>,
{
    type Error = bip32::Error;

    fn derive_verifying_key_bip32(
        &self,
        derivation_path: &DerivationPath,
    ) -> Result<VerifyingKey<P::Curve>, bip32::Error> {
        let public_key = self.verifying_key().map_err(|_| bip32::Error::Crypto)?;
        let tweaks = derive_tweaks::<P::Curve, Self::Error>(public_key, derivation_path)?;
        apply_tweaks_public(public_key, &tweaks)
    }
}

impl DeriveChildKey<TinyCurve64> for VerifyingKey<TinyCurve64> {
    type Error = bip32::Error;
    fn derive_verifying_key_bip32(
        &self,
        derivation_path: &DerivationPath,
    ) -> Result<VerifyingKey<TinyCurve64>, bip32::Error> {
        let pubkey: PublicKey<TinyCurve64> = self.into();
        let wrapped_pubkey: PublicKeyBip32<TinyCurve64> = pubkey.into();
        let tweaks = derive_tweaks::<TinyCurve64, Self::Error>(wrapped_pubkey, derivation_path)?;
        apply_tweaks_public(wrapped_pubkey, &tweaks)
    }
}
impl DeriveChildKey<Secp256k1> for VerifyingKey<Secp256k1> {
    type Error = bip32::Error;
    fn derive_verifying_key_bip32(
        &self,
        derivation_path: &DerivationPath,
    ) -> Result<VerifyingKey<Secp256k1>, bip32::Error> {
        let tweaks = derive_tweaks::<Secp256k1, Self::Error>(*self, derivation_path)?;
        apply_tweaks_public(*self, &tweaks)
    }
}

fn derive_tweaks<C, Err>(
    public_key: impl bip32::PublicKey + Clone,
    derivation_path: &DerivationPath,
) -> Result<Vec<PrivateKeyBytes>, Err>
where
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let mut public_key = public_key;

    // Note: deriving the initial chain code from public information. Is this okay? <–– PROBABLY NOT OK?
    let pubkey_bytes = public_key.to_bytes();
    let mut chain_code = <C as DigestPrimitive>::Digest::new()
        .chain_update(b"chain-code-derivation")
        .chain_update(pubkey_bytes)
        .finalize()
        .as_ref()
        .try_into()
        .expect("TODO(dp): map the error - chain code size mismatch");

    let mut tweaks = Vec::new();
    for child_number in derivation_path.iter() {
        let (tweak, new_chain_code) = public_key
            .derive_tweak(&chain_code, child_number)
            .expect("TODO(dp) map the error");
        public_key = public_key.derive_child(tweak).expect("TODO(dp) map the error");
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
    // TODO(dp): not sure if this is ok. Also: map the error to something sensible.
    VerifyingKey::from_sec1_bytes(public_key.to_bytes().as_ref()).map_err(|_e| bip32::Error::Decode)
}

fn apply_tweaks_private<C>(
    private_key: SigningKey<C>,
    tweaks: &[PrivateKeyBytes],
) -> Result<SigningKey<C>, bip32::Error>
where
    C: CurveArithmetic + PrimeCurve,
    <C as CurveArithmetic>::Scalar: SignPrimitive<C>,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    SigningKey<C>: bip32::PrivateKey,
{
    let mut private_key = private_key;
    for tweak in tweaks {
        private_key = private_key.derive_child(*tweak)?;
    }
    Ok(private_key)
}
