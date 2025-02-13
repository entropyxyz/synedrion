//! Schnorr proof of knowledge ($\Pi^{sch}$, Section A.1, Fig. 22).
//!
//! Publish $X$ and prove that we know a secret $x$ such that $g^x = X$,
//! where $g$ is the EC generator.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar},
    tools::{
        hashing::{Chain, Hashable, XofHasher},
        Secret,
    },
};

const HASH_TAG: &[u8] = b"P_sch";

/// Secret data the proof is based on (~ signing key)
#[derive(Debug, Clone)]
pub(crate) struct SchSecret(
    /// $\alpha$
    Secret<Scalar>,
);

impl SchSecret {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Secret::init_with(|| Scalar::random(rng)))
    }
}

/// Public data for the proof (~ verifying key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SchCommitment(Point);

impl SchCommitment {
    pub fn new(secret: &SchSecret) -> Self {
        Self(secret.0.mul_by_generator())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SchChallenge(Scalar);

impl SchChallenge {
    fn new(public: &Point, commitment: &SchCommitment, aux: &impl Hashable) -> Self {
        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            .chain(aux)
            .chain(public)
            .chain(commitment)
            .finalize_to_reader();
        Self(Scalar::from_xof_reader(&mut reader))
    }
}

/// ZK proof: Schnorr proof of knowledge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SchProof {
    challenge: SchChallenge,
    proof: Scalar,
}

impl SchProof {
    pub fn new(
        proof_secret: &SchSecret,
        x: &Secret<Scalar>,
        commitment: &SchCommitment,
        cap_x: &Point,
        aux: &impl Hashable,
    ) -> Self {
        let challenge = SchChallenge::new(cap_x, commitment, aux);
        let proof = *(&proof_secret.0 + x * challenge.0).expose_secret();
        Self { challenge, proof }
    }

    pub fn verify(&self, commitment: &SchCommitment, cap_x: &Point, aux: &impl Hashable) -> bool {
        let challenge = SchChallenge::new(cap_x, commitment, aux);
        challenge == self.challenge && self.proof.mul_by_generator() == commitment.0 + cap_x * challenge.0
    }
}

#[cfg(test)]
mod tests {
    use manul::{dev::BinaryFormat, session::WireFormat};
    use rand_core::OsRng;

    use super::{SchCommitment, SchProof, SchSecret};
    use crate::{curve::Scalar, tools::Secret};

    #[test]
    fn prove_and_verify() {
        let secret = Secret::init_with(|| Scalar::random(&mut OsRng));
        let public = secret.mul_by_generator();
        let aux: &[u8] = b"abcde";

        let proof_secret = SchSecret::random(&mut OsRng);
        let commitment = SchCommitment::new(&proof_secret);
        let proof = SchProof::new(&proof_secret, &secret, &commitment, &public, &aux);

        // Roundtrip works
        let res = BinaryFormat::serialize(proof);
        assert!(res.is_ok());
        let payload = res.unwrap();
        let proof: SchProof = BinaryFormat::deserialize(&payload).unwrap();

        assert!(proof.verify(&commitment, &public, &aux));
    }
}
