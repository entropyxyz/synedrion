//! Schnorr proof of knowledge ($\Pi^{sch}$, Section C.1, Fig. 22).
//!
//! Publish $X$ and prove that we know a secret $x$ such that $g^x = X$,
//! where $g$ is a EC generator.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::curve::{Point, Scalar};
use crate::tools::hashing::{Chain, Hash, Hashable};

/// Secret data the proof is based on (~ signing key)
#[derive(Clone)]
pub(crate) struct SchSecret(
    /// `\alpha`
    Scalar,
);

impl SchSecret {
    pub(crate) fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Scalar::random(rng))
    }
}

/// Public data for the proof (~ verifying key)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SchCommitment(Point);

impl SchCommitment {
    pub(crate) fn new(secret: &SchSecret) -> Self {
        Self(secret.0.mul_by_generator())
    }
}

impl Hashable for SchCommitment {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
struct SchChallenge(Scalar);

impl SchChallenge {
    fn new(aux: &impl Hashable, public: &Point, commitment: &SchCommitment) -> Self {
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
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SchProof {
    challenge: SchChallenge,
    proof: Scalar,
}

impl SchProof {
    /// Create a proof that we know the `secret`.
    pub(crate) fn new(
        proof_secret: &SchSecret,
        secret: &Scalar,
        commitment: &SchCommitment,
        public: &Point,
        aux: &impl Hashable,
    ) -> Self {
        let challenge = SchChallenge::new(aux, public, commitment);
        let proof = proof_secret.0 + &challenge.0 * secret;
        Self { challenge, proof }
    }

    /// Verify that the proof is correct for a secret corresponding to the given `public`.
    pub(crate) fn verify(
        &self,
        commitment: &SchCommitment,
        public: &Point,
        aux: &impl Hashable,
    ) -> bool {
        let challenge = SchChallenge::new(aux, public, commitment);
        challenge == self.challenge
            && self.proof.mul_by_generator() == commitment.0 + public * &challenge.0
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{SchCommitment, SchProof, SchSecret};
    use crate::curve::Scalar;

    #[test]
    fn prove_and_verify() {
        let secret = Scalar::random(&mut OsRng);
        let public = secret.mul_by_generator();
        let aux: &[u8] = b"abcde";

        let proof_secret = SchSecret::random(&mut OsRng);
        let commitment = SchCommitment::new(&proof_secret);
        let proof = SchProof::new(&proof_secret, &secret, &commitment, &public, &aux);
        assert!(proof.verify(&commitment, &public, &aux));
    }
}
