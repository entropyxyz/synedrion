use crate::SchemeParams;
use ecdsa::{RecoveryId, Signature as BackendSignature, VerifyingKey};
use primeorder::elliptic_curve::group::Curve as _;

#[cfg(test)]
use rand_core::CryptoRngCore;

use super::arithmetic::{Point, Scalar};

/// A wrapper for a signature and public key recovery info.
// TODO(dp): `Copy` would have been nice here but would require `FieldBytesSize as Add>::Output` which is possible but probably unpalatable.
#[derive(Debug, Clone)]
pub struct RecoverableSignature<P: SchemeParams> {
    signature: BackendSignature<P::Curve>,
    recovery_id: RecoveryId,
}

impl<P> RecoverableSignature<P>
where
    P: SchemeParams,
{
    #[cfg(test)]
    pub(crate) fn random(rng: &mut impl CryptoRngCore) -> Option<Self> {
        let sk = ecdsa::SigningKey::random(rng);
        let (signature, recovery_id) = sk.sign_recoverable(b"test message").ok()?;
        Some(Self { signature, recovery_id })
    }

    // TODO(dp): investigate call-sites of this and see if we can pass by value instead and remove the clones.
    pub(crate) fn from_scalars(r: &Scalar<P>, s: &Scalar<P>, vkey: &Point<P>, message: &Scalar<P>) -> Option<Self> {
        let signature = BackendSignature::from_scalars(r.to_backend(), s.to_backend()).ok()?;

        // Normalize the `s` component.
        // `BackendSignature`'s constructor does not require `s` to be normalized,
        // but consequent usage of it may fail otherwise.
        let signature = signature.normalize_s().unwrap_or(signature);

        let message_bytes = message.clone().to_be_bytes();
        let recovery_id = RecoveryId::trial_recovery_from_prehash(
            &VerifyingKey::from_affine(vkey.clone().to_backend().to_affine()).ok()?,
            &message_bytes,
            &signature,
        )
        .ok()?;

        Some(Self { signature, recovery_id })
    }

    /// Unwraps into the signature and recovery info objects from the backend crate.
    pub fn to_backend(self) -> (BackendSignature<P::Curve>, RecoveryId) {
        (self.signature, self.recovery_id)
    }
}
