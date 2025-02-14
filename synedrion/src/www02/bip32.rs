use core::{fmt::Debug, ops::Add};

use crate::{
    curve::{Point, Scalar},
    SchemeParams,
};
use alloc::vec::Vec;
use bip32::{DerivationPath, PrivateKey as _, PrivateKeyBytes, PublicKey as _};
use digest::generic_array::ArrayLength;

use digest::Digest;
use ecdsa::{
    hazmat::{DigestPrimitive, SignPrimitive},
    SigningKey, VerifyingKey,
};
use primeorder::elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, PrimeCurve,
};
use serde::{Deserialize, Serialize};

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

impl<C> DeriveChildKey<C> for VerifyingKey<C>
where
    VerifyingKey<C>: bip32::PublicKey,
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    type Error = bip32::Error;
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey<C>, bip32::Error> {
        let tweaks = derive_tweaks::<C, Self::Error>(*self, derivation_path)?;
        apply_tweaks_public(*self, &tweaks)
    }
}

fn derive_tweaks<C, Err>(
    public_key: VerifyingKey<C>,
    derivation_path: &DerivationPath,
) -> Result<Vec<PrivateKeyBytes>, Err>
where
    VerifyingKey<C>: bip32::PublicKey,
    C: CurveArithmetic + PrimeCurve + DigestPrimitive,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let mut public_key = public_key;

    // Note: deriving the initial chain code from public information. Is this okay? <–– PROBABLY NOT OK?
    let pubkey_bytes = public_key.clone().as_affine().to_encoded_point(true);
    let pubkey_bytes = pubkey_bytes.as_bytes();
    let mut chain_code = <C as DigestPrimitive>::Digest::new()
        .chain_update(b"chain-code-derivation")
        .chain_update(&pubkey_bytes)
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
    public_key: VerifyingKey<C>,
    tweaks: &[PrivateKeyBytes],
) -> Result<VerifyingKey<C>, bip32::Error>
where
    C: CurveArithmetic + PrimeCurve,
    VerifyingKey<C>: bip32::PublicKey,
{
    let mut public_key = public_key;
    for tweak in tweaks {
        public_key = public_key.derive_child(*tweak)?;
    }
    Ok(public_key)
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
