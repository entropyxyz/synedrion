use k256::ecdsa::{RecoveryId, Signature as BackendSignature, VerifyingKey};

use super::arithmetic::{Point, Scalar};

/// A wrapper for a signature and public key recovery info.
#[derive(Debug, Clone, Copy)]
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
        let signature = BackendSignature::from_scalars(r.to_backend(), s.to_backend()).ok()?;

        // Normalize the `s` component.
        // `BackendSignature`'s constructor does not require `s` to be normalized,
        // but consequent usage of it may fail otherwise.
        let signature = signature.normalize_s().unwrap_or(signature);

        let message_bytes = message.to_bytes();
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

    /// Unwraps into the signature and recovery info objects from the backend crate.
    pub fn to_backend(self) -> (BackendSignature, RecoveryId) {
        (self.signature, self.recovery_id)
    }
}
