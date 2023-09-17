//! ZKP of Ring-Pedersen parameters ($\Pi^{prm}$, Section 6.4, Fig. 17).
//!
//! Publish $(N, s, t)$ and prove that we know a secret $\lambda$ such that
//! $s = t^\lambda \mod N$.

use alloc::vec::Vec;

use rand_core::CryptoRngCore;

use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{
    PaillierParams, PublicKeyPaillierPrecomputed, RPParamsMod, RPSecret,
    SecretKeyPaillierPrecomputed,
};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::{
    subtle::{Choice, ConditionallySelectable},
    Bounded, Retrieve, UintModLike,
};

/// Secret data the proof is based on (~ signing key)
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrmSecret<P: SchemeParams> {
    public_key: PublicKeyPaillierPrecomputed<P::Paillier>,
    /// `a_i`
    secret: Vec<Bounded<<P::Paillier as PaillierParams>::Uint>>,
}

impl<P: SchemeParams> PrmSecret<P> {
    pub(crate) fn random(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillierPrecomputed<P::Paillier>,
    ) -> Self {
        let secret = (0..P::SECURITY_PARAMETER)
            .map(|_| sk.random_field_elem(rng))
            .collect();
        Self {
            public_key: sk.public_key().clone(),
            secret,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrmCommitment<P: SchemeParams>(Vec<<P::Paillier as PaillierParams>::Uint>);

impl<P: SchemeParams> PrmCommitment<P> {
    pub(crate) fn new(
        secret: &PrmSecret<P>,
        base: &<P::Paillier as PaillierParams>::UintMod,
    ) -> Self {
        let commitment = secret
            .secret
            .iter()
            .map(|a| base.pow_bounded(a).retrieve())
            .collect();
        Self(commitment)
    }
}

impl<P: SchemeParams> Hashable for PrmCommitment<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrmChallenge(Vec<bool>);

impl PrmChallenge {
    fn new<P: SchemeParams>(aux: &impl Hashable, commitment: &PrmCommitment<P>) -> Self {
        // TODO: generate m/8 random bytes instead and fill the vector bit by bit.
        // CHECK: should we use an actual RNG here instead of variable-sized hash?
        let bytes = XofHash::new_with_dst(b"prm-challenge")
            .chain(aux)
            .chain(commitment)
            .finalize_boxed(P::SECURITY_PARAMETER);
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
pub(crate) struct PrmProof<P: SchemeParams> {
    commitment: PrmCommitment<P>,
    challenge: PrmChallenge,
    proof: Vec<Bounded<<P::Paillier as PaillierParams>::Uint>>,
}

impl<P: SchemeParams> PrmProof<P> {
    /// Create a proof that we know the `secret`
    /// (the power that was used to create RP parameters).
    pub(crate) fn random(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillierPrecomputed<P::Paillier>,
        rp_secret: &RPSecret<P::Paillier>,
        rp: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        let proof_secret = PrmSecret::<P>::random(rng, sk);
        let commitment = PrmCommitment::new(&proof_secret, &rp.base);

        let totient = sk.totient_nonzero();
        let challenge = PrmChallenge::new(aux, &commitment);
        let proof = proof_secret
            .secret
            .iter()
            .zip(challenge.0.iter())
            .map(|(a, e)| {
                let x = a.add_mod(rp_secret.as_ref(), &totient);
                let choice = Choice::from(*e as u8);
                Bounded::conditional_select(a, &x, choice)
            })
            .collect();
        Self {
            commitment,
            proof,
            challenge,
        }
    }

    /// Verify that the proof is correct for a secret corresponding to the given RP parameters.
    pub(crate) fn verify(&self, rp: &RPParamsMod<P::Paillier>, aux: &impl Hashable) -> bool {
        let modulus = rp.public_key().precomputed_modulus();

        let challenge = PrmChallenge::new(aux, &self.commitment);
        if challenge != self.challenge {
            return false;
        }

        for i in 0..challenge.0.len() {
            let z = self.proof[i];
            let e = challenge.0[i];
            let a = <P::Paillier as PaillierParams>::UintMod::new(&self.commitment.0[i], modulus);
            let pwr = rp.base.pow_bounded(&z);
            let test = if e { pwr == a * rp.power } else { pwr == a };
            if !test {
                return false;
            }
        }
        true
    }
}

impl<P: SchemeParams> Hashable for PrmProof<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.challenge).chain(&self.proof)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::PrmProof;
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::paillier::{RPParamsMod, RPSecret, SecretKeyPaillier};

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let rp_secret = RPSecret::random(&mut OsRng, &sk);
        let rp = RPParamsMod::random_with_secret(&mut OsRng, &rp_secret, pk);

        let aux: &[u8] = b"abcde";

        let proof = PrmProof::<Params>::random(&mut OsRng, &sk, &rp_secret, &rp, &aux);
        assert!(proof.verify(&rp, &aux));
    }
}
