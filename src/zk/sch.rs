//! Schnorr proof of knowledge ($\Pi^{sch}$, Section A.1, Fig. 22).
//!
//! Publish $X$ and prove that we know a secret $x$ such that $g^x = X$,
//! where $g$ is the EC generator.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar},
    params::SchemeParams,
    tools::{
        hashing::{Chain, Hashable, Hasher},
        Secret,
    },
};

const HASH_TAG: &[u8] = b"P_sch";

/// Secret data the proof is based on (~ signing key)
#[derive(Debug, Clone)]
pub(crate) struct SchSecret<P: SchemeParams>(
    /// `\alpha`
    Secret<Scalar<P>>,
);

impl<P: SchemeParams> SchSecret<P> {
    pub fn random(rng: &mut dyn CryptoRngCore) -> Self {
        Self(Secret::init_with(|| Scalar::random(rng)))
    }
}

/// Public data for the proof (~ verifying key)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "Point<P>: for<'x> Deserialize<'x>"))]
pub(crate) struct SchCommitment<P: SchemeParams>(Point<P>);

impl<P: SchemeParams> SchCommitment<P> {
    pub fn new(secret: &SchSecret<P>) -> Self {
        Self(secret.0.mul_by_generator())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "Scalar<P>: for<'x> Deserialize<'x>"))]
struct SchChallenge<P: SchemeParams>(Scalar<P>);

impl<P: SchemeParams> SchChallenge<P> {
    fn new(public: &Point<P>, commitment: &SchCommitment<P>, aux: &impl Hashable) -> Self {
        let mut reader = Hasher::<P::Digest>::new_with_dst(HASH_TAG)
            .chain(aux)
            .chain(public)
            .chain(commitment)
            .finalize_to_reader();
        Self(Scalar::from_xof_reader(&mut reader))
    }
}

/// ZK proof: Schnorr proof of knowledge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "for<'x> SchChallenge<P>: Deserialize<'x>"))]
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
        challenge == self.challenge && (commitment.0 + cap_x * challenge.0) == self.proof.mul_by_generator()
    }
}

#[cfg(test)]
mod tests {
    use manul::{dev::BinaryFormat, session::WireFormat};
    use rand_core::OsRng;

    use super::{SchCommitment, SchProof, SchSecret};
    use crate::{curve::Scalar, dev::TestParams, tools::Secret};

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;

        let secret = Secret::init_with(|| Scalar::<Params>::random(&mut OsRng));
        let public = secret.mul_by_generator();
        let aux: &[u8] = b"abcde";

        let proof_secret = SchSecret::random(&mut OsRng);
        let commitment = SchCommitment::new(&proof_secret);
        let proof = SchProof::new(&proof_secret, &secret, &commitment, &public, &aux);

        // Serialization roundtrip
        let serialized = BinaryFormat::serialize(proof).unwrap();
        let proof = BinaryFormat::deserialize::<SchProof<Params>>(&serialized).unwrap();

        assert!(proof.verify(&commitment, &public, &aux));
    }
}
