use ecdsa::SignatureBytes; // TODO: can it be accessed through `k256`?
use k256::{
    ecdsa::{
        signature::{DigestSigner, DigestVerifier},
        RecoveryId, Signature as BackendSignature, SigningKey, VerifyingKey,
    },
    Secp256k1,
};
use rand_core::CryptoRngCore;
use serde::{de::Error as SerdeDeError, Deserialize, Deserializer, Serialize, Serializer};

use super::arithmetic::{Point, Scalar};
use crate::tools::hashing::BackendDigest;

// TODO: needs serialization support
#[derive(Clone)]
pub struct Signer(SigningKey);

impl Signer {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(SigningKey::random(rng))
    }

    pub fn verifier(&self) -> Verifier {
        Verifier(*self.0.verifying_key())
    }

    pub fn sign_digest(&self, digest: BackendDigest) -> Signature {
        Signature(self.0.sign_digest(digest))
    }
}

// TODO: needs serialization support
#[derive(Clone)]
pub struct Verifier(VerifyingKey);

impl Verifier {
    pub fn verify_digest(
        &self,
        digest: BackendDigest,
        signature: &Signature,
    ) -> Result<(), ecdsa::Error> {
        self.0.verify_digest(digest, &signature.0)
    }
}

#[derive(Clone, Debug)]
pub struct Signature(BackendSignature);

impl Signature {}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serdect::array::serialize_hex_lower_or_bin(&self.0.to_bytes(), serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut buffer = SignatureBytes::<Secp256k1>::default();
        serdect::array::deserialize_hex_or_bin(&mut buffer, deserializer)?;
        Ok(Self(
            BackendSignature::from_bytes(&buffer).map_err(D::Error::custom)?,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct RecoverableSignature {
    signature: BackendSignature,
    recovery_id: RecoveryId,
}

impl RecoverableSignature {
    pub(crate) fn from_scalars(
        r: &Scalar,
        s: &Scalar,
        vkey: &Point,
        message: &Scalar,
    ) -> Option<Self> {
        // TODO: call `normalize_s()` on the result?
        // TODO: pass a message too and derive the recovery byte?
        let signature = BackendSignature::from_scalars(r.to_backend(), s.to_backend()).ok()?;
        let message_bytes = message.to_be_bytes();
        let recovery_id = RecoveryId::trial_recovery_from_prehash(
            &VerifyingKey::from_affine(vkey.to_backend().to_affine()).ok()?,
            &message_bytes,
            &signature,
        )
        .ok()?;

        Some(Self {
            signature,
            recovery_id,
        })
    }

    pub fn to_backend(self) -> (BackendSignature, RecoveryId) {
        (self.signature, self.recovery_id)
    }
}
