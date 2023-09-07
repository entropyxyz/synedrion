//! ZKP of Ring-Pedersen parameters ($\Pi^{prm}$, Section 6.4, Fig. 17).
//!
//! Publish $(N, s, t)$ and prove that we know a secret $\lambda$ such that
//! $s = t^\lambda \mod N$.

use alloc::vec::Vec;

use rand_core::CryptoRngCore;

use serde::{Deserialize, Serialize};

use crate::paillier::{
    PaillierParams, PublicKeyPaillier, RPParamsMod, RPSecret, SecretKeyPaillier,
};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::{Pow, Retrieve, UintLike, UintModLike, Zero};

/// Secret data the proof is based on (~ signing key)
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrmSecret<P: PaillierParams> {
    public_key: PublicKeyPaillier<P>,
    /// `a_i`
    secret: Vec<P::DoubleUint>,
}

impl<P: PaillierParams> PrmSecret<P> {
    pub(crate) fn random(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillier<P>,
        security_parameter: usize,
    ) -> Self {
        let secret = (0..security_parameter)
            .map(|_| sk.random_field_elem(rng))
            .collect();
        Self {
            public_key: sk.public_key(),
            secret,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrmCommitment<P: PaillierParams>(Vec<P::DoubleUint>);

impl<P: PaillierParams> PrmCommitment<P> {
    pub(crate) fn new(secret: &PrmSecret<P>, base: &P::DoubleUintMod) -> Self {
        let commitment = secret
            .secret
            .iter()
            .map(|a| base.pow(a).retrieve())
            .collect();
        Self(commitment)
    }

    fn security_parameter(&self) -> usize {
        self.0.len()
    }
}

impl<P: PaillierParams> Hashable for PrmCommitment<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrmChallenge(Vec<bool>);

impl PrmChallenge {
    fn new<P: PaillierParams>(aux: &impl Hashable, commitment: &PrmCommitment<P>) -> Self {
        // TODO: generate m/8 random bytes instead and fill the vector bit by bit.
        // CHECK: should we use an actual RNG here instead of variable-sized hash?
        let bytes = XofHash::new_with_dst(b"prm-challenge")
            .chain(aux)
            .chain(commitment)
            .finalize_boxed(commitment.security_parameter());
        Self(bytes.as_ref().iter().map(|b| b & 1 == 1).collect())
    }
}

impl Hashable for PrmChallenge {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "PrmCommitment<P>: Serialize"))]
#[serde(bound(deserialize = "PrmCommitment<P>: for<'x> Deserialize<'x>"))]
pub(crate) struct PrmProof<P: PaillierParams> {
    commitment: PrmCommitment<P>,
    challenge: PrmChallenge,
    proof: Vec<P::DoubleUint>,
}

impl<P: PaillierParams> PrmProof<P> {
    /// Create a proof that we know the `secret`
    /// (the power that was used to create RP parameters).
    pub(crate) fn random(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillier<P>,
        rp_secret: &RPSecret<P>,
        rp: &RPParamsMod<P>,
        aux: &impl Hashable,
        security_parameter: usize,
    ) -> Self {
        let proof_secret = PrmSecret::random(rng, sk, security_parameter);
        let commitment = PrmCommitment::new(&proof_secret, &rp.base);

        let totient = sk.totient();
        let zero = P::DoubleUint::ZERO;
        let challenge = PrmChallenge::new(aux, &commitment);
        let proof = proof_secret
            .secret
            .iter()
            .zip(challenge.0.iter())
            .map(|(a, e)| a.add_mod(if *e { rp_secret.as_ref() } else { &zero }, &totient))
            .collect();
        Self {
            commitment,
            proof,
            challenge,
        }
    }

    /// Verify that the proof is correct for a secret corresponding to the given RP parameters.
    pub(crate) fn verify(
        &self,
        pk: &PublicKeyPaillier<P>,
        rp: &RPParamsMod<P>,
        aux: &impl Hashable,
    ) -> bool {
        let modulus = pk.modulus();

        let challenge = PrmChallenge::new(aux, &self.commitment);
        if challenge != self.challenge {
            return false;
        }

        for i in 0..challenge.0.len() {
            let z = self.proof[i];
            let e = challenge.0[i];
            let a = P::DoubleUintMod::new(&self.commitment.0[i], &modulus);
            let test = if e {
                rp.base.pow(&z) == a * rp.power
            } else {
                rp.base.pow(&z) == a
            };
            if !test {
                return false;
            }
        }
        true
    }
}

impl<P: PaillierParams> Hashable for PrmProof<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.challenge).chain(&self.proof)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::PrmProof;
    use crate::paillier::{PaillierTest, RPParamsMod, RPSecret, SecretKeyPaillier};

    #[test]
    fn prove_and_verify() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();
        let security_parameter = 10;

        let rp_secret = RPSecret::random(&mut OsRng, &sk);
        let rp = RPParamsMod::random_with_secret(&mut OsRng, &rp_secret, &pk);

        let aux: &[u8] = b"abcde";

        let proof = PrmProof::random(&mut OsRng, &sk, &rp_secret, &rp, &aux, security_parameter);
        assert!(proof.verify(&pk, &rp, &aux));
    }
}
