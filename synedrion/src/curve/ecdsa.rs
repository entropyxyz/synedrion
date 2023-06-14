use k256::ecdsa::{RecoveryId, Signature as BackendSignature, VerifyingKey};

use super::arithmetic::{Point, Scalar};

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
