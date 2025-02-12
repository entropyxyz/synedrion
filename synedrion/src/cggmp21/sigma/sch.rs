//! Schnorr proof of knowledge ($\Pi^{sch}$, Section C.1, Fig. 22).
//!
//! Publish $X$ and prove that we know a secret $x$ such that $g^x = X$,
//! where $g$ is a EC generator.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar},
    tools::{
        hashing::{Chain, FofHasher, Hashable},
        Secret,
    },
    SchemeParams,
};

const HASH_TAG: &[u8] = b"P_sch";

/// Secret data the proof is based on (~ signing key)
#[derive(Debug, Clone)]
pub(crate) struct SchSecret<P: SchemeParams>(
    /// `\alpha`
    Secret<Scalar<P>>,
);

impl<P: SchemeParams> SchSecret<P> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Secret::init_with(|| Scalar::random(rng)))
    }
}

/// Public data for the proof (~ verifying key)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "for<'x> P: Deserialize<'x>"))]
pub(crate) struct SchCommitment<P: SchemeParams>(Point<P>);

impl<P: SchemeParams> SchCommitment<P> {
    pub fn new(secret: &SchSecret<P>) -> Self {
        Self(secret.0.mul_by_generator())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "for<'x> P: Deserialize<'x>"))]
struct SchChallenge<P: SchemeParams>(Scalar<P>);

impl<P: SchemeParams> SchChallenge<P> {
    fn new(public: &Point<P>, commitment: &SchCommitment<P>, aux: &impl Hashable) -> Self {
        Self(
            FofHasher::new_with_dst(HASH_TAG)
                .chain(aux)
                .chain(public)
                .chain(commitment)
                .finalize_to_scalar(),
        )
    }
}

/**
ZK proof: Schnorr proof of knowledge.

Secret inputs:
- scalar $x$.

Public inputs:
- Point $X = g * x$, where $g$ is the curve generator.
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "for<'x> P: Deserialize<'x>"))]
pub(crate) struct SchProof<P: SchemeParams> {
    challenge: SchChallenge<P>,
    proof: Scalar<P>,
}

impl<P: SchemeParams> SchProof<P> {
    pub fn new(
        proof_secret: &SchSecret<P>,
        x: &Secret<Scalar<P>>,
        commitment: &SchCommitment<P>,
        cap_x: &Point<P>,
        aux: &impl Hashable,
    ) -> Self {
        let challenge = SchChallenge::new(cap_x, commitment, aux);
        let proof: Scalar<P> = *(&proof_secret.0 + x * challenge.0).expose_secret();
        Self { challenge, proof }
    }

    pub fn verify(&self, commitment: &SchCommitment<P>, cap_x: &Point<P>, aux: &impl Hashable) -> bool {
        let challenge = SchChallenge::new(cap_x, commitment, aux);
        challenge == self.challenge && (commitment.0 + cap_x * &challenge.0) == self.proof.mul_by_generator()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{SchCommitment, SchProof, SchSecret};
    use crate::{curve::Scalar, tools::Secret, TestParams};

    #[test]
    fn prove_and_verify() {
        let secret = Secret::init_with(|| Scalar::<TestParams>::random(&mut OsRng));
        let public = secret.mul_by_generator();
        let aux: &[u8] = b"abcde";

        let proof_secret = SchSecret::random(&mut OsRng);
        let commitment = SchCommitment::new(&proof_secret);
        let proof = SchProof::new(&proof_secret, &secret, &commitment, &public, &aux);
        assert!(proof.verify(&commitment, &public, &aux));
    }
}
