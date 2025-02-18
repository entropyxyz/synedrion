use core::{fmt::Debug, ops::Add};

use crate::{
    curve::{Point, Scalar},
    tools::Secret,
    ProductionParams112, SchemeParams, TestParams,
};
use alloc::vec::Vec;
use bip32::{ChainCode, DerivationPath, PrivateKeyBytes};
use digest::generic_array::ArrayLength;

use digest::typenum::Unsigned;
use digest::Digest;
use ecdsa::{
    hazmat::{DigestPrimitive, SignPrimitive},
    SigningKey, VerifyingKey,
};
use primeorder::elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, PrimeCurve, PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};
use tiny_curve::{PrivateKeyBip32, PublicKeyBip32};

use super::ThresholdKeyShare;

/// Used for deriving child keys from a parent type.
pub trait DeriveChildKey<C: CurveArithmetic + PrimeCurve>: Sized {
    /// The error type.
    type Error;
    /// Return a verifying key derived from the given type using the BIP-32 scheme.
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey<C>, Self::Error>;
    /// Bla
    fn derive_bip32(&self, _derivation_path: &DerivationPath) -> Result<Self, Self::Error> {
        unimplemented!()
    }
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

impl<I> DeriveChildKey<<TestParams as SchemeParams>::Curve> for ThresholdKeyShare<TestParams, I>
where
    I: Clone + Ord + PartialEq + Debug + Serialize + for<'x> Deserialize<'x>,
{
    type Error = bip32::Error;

    fn derive_verifying_key_bip32(
        &self,
        derivation_path: &DerivationPath,
    ) -> Result<VerifyingKey<<TestParams as SchemeParams>::Curve>, bip32::Error> {
        let pubkey: PublicKey<_> = self.verifying_key().map_err(|_| bip32::Error::Crypto)?.into();
        let wrapped_pubkey: PublicKeyBip32<_> = pubkey.into();
        let tweaks =
            derive_tweaks::<<TestParams as SchemeParams>::Curve, Self::Error>(wrapped_pubkey, derivation_path)?;
        apply_tweaks_public(wrapped_pubkey, &tweaks)
    }

    fn derive_bip32(&self, derivation_path: &DerivationPath) -> Result<Self, bip32::Error> {
        type C = <TestParams as SchemeParams>::Curve;
        let pk: PublicKey<_> = self.verifying_key().map_err(|_| bip32::Error::Crypto)?.into();
        let wrapped_pk: PublicKeyBip32<_> = pk.into();

        let mut tweaks = derive_tweaks::<C, bip32::Error>(wrapped_pk, derivation_path)?;
        // Write zeros to the high bytes of the tweaks so that the resulting Scalars fit within the small curve's modulus.
        tweaks.iter_mut().for_each(|tweak| {
            tweak[..<C as Curve>::FieldBytesSize::USIZE].fill(0);
        });

        // Will fail here if secret share is zero
        let secret_share = self.secret_share.clone().to_signing_key().ok_or(bip32::Error::Crypto)?;
        let sk: SecretKey<_> = secret_share.into();
        use bip32::PrivateKey as _;
        let mut wrapped_ss: PrivateKeyBip32<C> = sk.into();
        for tweak in tweaks.clone() {
            wrapped_ss = wrapped_ss.derive_child(tweak)?;
        }
        let secret_share = Scalar::<TestParams>::try_from_be_bytes(
            wrapped_ss.to_bytes()[32 - Scalar::<TestParams>::repr_len()..].as_ref(),
        )
        .map_err(|_e| Self::Error::Decode)?;
        let secret_share = Secret::init_with(|| secret_share);

        let public_shares = self
            .public_shares
            .clone()
            .into_iter()
            .map(|(id, point)| {
                // Will fail here if the final or one of the intermediate points is an identity
                point
                    .to_verifying_key()
                    .ok_or(bip32::Error::Crypto)
                    .map(|vkey| {
                        // Convert the VerifyingKey to something we can apply tweaks to.
                        let pk: PublicKey<_> = vkey.into();
                        let wrapped_pk: PublicKeyBip32<_> = pk.into();
                        wrapped_pk
                    })
                    .and_then(|bip32_pubkey| apply_tweaks_public(bip32_pubkey, &tweaks))
                    .map(|vkey| (id, Point::from_verifying_key(&vkey)))
            })
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
impl<I> DeriveChildKey<<ProductionParams112 as SchemeParams>::Curve> for ThresholdKeyShare<ProductionParams112, I>
where
    I: Clone + Ord + PartialEq + Debug + Serialize + for<'x> Deserialize<'x>,
{
    type Error = bip32::Error;

    fn derive_verifying_key_bip32(
        &self,
        derivation_path: &DerivationPath,
    ) -> Result<VerifyingKey<<ProductionParams112 as SchemeParams>::Curve>, bip32::Error> {
        let public_key = self.verifying_key().map_err(|_| bip32::Error::Crypto)?;
        let tweaks =
            derive_tweaks::<<ProductionParams112 as SchemeParams>::Curve, Self::Error>(public_key, derivation_path)?;
        apply_tweaks_public(public_key, &tweaks)
    }

    fn derive_bip32(&self, derivation_path: &DerivationPath) -> Result<Self, Self::Error> {
        self.derive_bip32(derivation_path)
    }
}

impl DeriveChildKey<<TestParams as SchemeParams>::Curve> for VerifyingKey<<TestParams as SchemeParams>::Curve> {
    type Error = bip32::Error;
    fn derive_verifying_key_bip32(
        &self,
        derivation_path: &DerivationPath,
    ) -> Result<VerifyingKey<<TestParams as SchemeParams>::Curve>, bip32::Error> {
        let pubkey: PublicKey<_> = self.into();
        let wrapped_pubkey: PublicKeyBip32<_> = pubkey.into();
        let tweaks =
            derive_tweaks::<<TestParams as SchemeParams>::Curve, Self::Error>(wrapped_pubkey, derivation_path)?;
        apply_tweaks_public(wrapped_pubkey, &tweaks)
    }
}
impl DeriveChildKey<<ProductionParams112 as SchemeParams>::Curve>
    for VerifyingKey<<ProductionParams112 as SchemeParams>::Curve>
{
    type Error = bip32::Error;
    fn derive_verifying_key_bip32(
        &self,
        derivation_path: &DerivationPath,
    ) -> Result<VerifyingKey<<ProductionParams112 as SchemeParams>::Curve>, bip32::Error> {
        let tweaks =
            derive_tweaks::<<ProductionParams112 as SchemeParams>::Curve, Self::Error>(*self, derivation_path)?;
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
    let chain_code_ref = <C as DigestPrimitive>::Digest::new()
        .chain_update(b"chain-code-derivation")
        .chain_update(pubkey_bytes)
        .finalize();
    let mut chain_code: ChainCode = Default::default();
    let len = chain_code_ref.len().min(chain_code.len());
    chain_code[..len].copy_from_slice(chain_code_ref[..len].as_ref());

    let mut tweaks = Vec::new();
    for child_number in derivation_path.iter() {
        let (mut tweak, new_chain_code) = public_key
            .derive_tweak(&chain_code, child_number)
            .expect("TODO(dp) map the error - derive_tweak");
        if <C as Curve>::FieldBytesSize::USIZE < 32 {
            tweak[..<C as Curve>::FieldBytesSize::USIZE].fill(0);
        }
        tracing::debug!("[derive_tweaks] tweak: {:?}", tweak);
        // For this to work the `tweak` must be at least 8 bytes long AND the high bytes must all be zero, otherwise TinyCurve cannot build a scalar from it.
        public_key = public_key
            .derive_child(tweak)
            .expect("TODO(dp) map the error - derive_child");
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
    tracing::info!("apply_tweaks_public: {:?}", public_key.to_bytes());
    let mut public_key = public_key;
    for tweak in tweaks {
        public_key = public_key.derive_child(*tweak)?;
    }
    let offset = 32 - <C as Curve>::FieldBytesSize::USIZE;
    // TODO(dp): not sure if this is ok. Also: map the error to something sensible.
    VerifyingKey::from_sec1_bytes(public_key.to_bytes()[offset..].as_ref()).map_err(|_e| bip32::Error::Decode)
}

// TODO(dp): Only used by the ThresholdKeyShare::derive_bip32 method. Can we move this there?
fn apply_tweaks_private<C>(
    private_key: impl bip32::PrivateKey + Clone,
    tweaks: &[PrivateKeyBytes],
) -> Result<SigningKey<C>, bip32::Error>
where
    C: CurveArithmetic + PrimeCurve,
    <C as CurveArithmetic>::Scalar: SignPrimitive<C>,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
{
    let mut private_key = private_key;
    for tweak in tweaks {
        private_key = private_key.derive_child(*tweak)?;
    }
    SigningKey::from_slice(private_key.to_bytes().as_ref()).map_err(|_e| bip32::Error::Decode)
}
