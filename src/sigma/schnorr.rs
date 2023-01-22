//! Schnorr proof of knowledge ($\Pi_{sch}$, Section C.1, Fig. 22).
//!
//! Publish $X$ and prove that we know a secret $x$ such that $g^x = X$,
//! where $g$ is a EC generator.
use crate::tools::group::{NonZeroScalar, Point, Scalar};
use crate::tools::hashing::{Hash, Hashable};

/// Secret data the proof is based on (~ signing key)
pub(crate) struct SchnorrProofSecret(NonZeroScalar);

impl SchnorrProofSecret {
    pub(crate) fn new() -> Self {
        Self(NonZeroScalar::random())
    }

    pub(crate) fn commitment(&self) -> SchnorrCommitment {
        SchnorrCommitment(&Point::GENERATOR * &self.0)
    }
}

/// Public data for the proof (~ verifying key)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SchnorrCommitment(Point);

impl Hashable for SchnorrCommitment {
    fn chain(&self, digest: Hash) -> Hash {
        digest.chain(&self.0)
    }
}

#[derive(Clone, PartialEq)]
struct Challenge(Scalar);

impl Challenge {
    fn new(aux: &impl Hashable, public: &Point, commitment: &SchnorrCommitment) -> Self {
        Self(
            Hash::new_with_dst(b"challenge-Schnorr")
                .chain(aux)
                .chain(public)
                .chain(commitment)
                .finalize_to_scalar(),
        )
    }
}

/// Schnorr PoK of a secret scalar.
#[derive(Clone)]
pub(crate) struct SchnorrProof {
    commitment: SchnorrCommitment,
    challenge: Challenge,
    proof: Scalar, // TODO: better name?
}

impl SchnorrProof {
    /// Create a proof that we know the `secret`.
    pub(crate) fn new(
        proof_secret: &SchnorrProofSecret,
        secret: &NonZeroScalar,
        aux: &impl Hashable,
    ) -> Self {
        let commitment = proof_secret.commitment();
        let public = &Point::GENERATOR * secret;
        let challenge = Challenge::new(aux, &public, &commitment);
        let proof = &proof_secret.0 + &(&challenge.0 * secret);
        Self {
            commitment,
            challenge,
            proof,
        }
    }

    /// Verify that the proof is correct for a secret corresponding to the given `public`.
    pub(crate) fn verify(
        &self,
        commitment: &SchnorrCommitment,
        public: &Point,
        aux: &impl Hashable,
    ) -> bool {
        // TODO: why do we save the commitment in the proof?
        // If the commitment is wrong, the verification in the next line just fails, right?
        if &self.commitment != commitment {
            return false;
        }

        // TODO: why do we save the challenge in the proof if we're reconstructing it anyway?
        let reconstructed_challenge = Challenge::new(aux, public, &self.commitment);
        self.challenge == reconstructed_challenge
            && &Point::GENERATOR * &self.proof == &self.commitment.0 + &(public * &self.challenge.0)
    }
}
