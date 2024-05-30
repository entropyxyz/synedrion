//! ZKP of Ring-Pedersen parameters ($\Pi^{prm}$, Section 6.4, Fig. 17).
//!
//! Publish $(N, s, t)$ and prove that we know a secret $\lambda$ such that
//! $s = t^\lambda \mod N$.

use alloc::{vec, vec::Vec};

use digest::XofReader;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{PaillierParams, RPParamsMod, RPSecret, SecretKeyPaillierPrecomputed};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::{
    subtle::{Choice, ConditionallySelectable},
    Bounded, ToMod,
};

const HASH_TAG: &[u8] = b"P_prm";

/// Secret data the proof is based on ($a_i$).
#[derive(Clone)]
struct PrmSecret<P: SchemeParams>(Vec<Bounded<<P::Paillier as PaillierParams>::Uint>>);

impl<P: SchemeParams> PrmSecret<P> {
    fn random(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillierPrecomputed<P::Paillier>,
    ) -> Self {
        let secret = (0..P::SECURITY_PARAMETER)
            .map(|_| sk.random_field_elem(rng))
            .collect();
        Self(secret)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrmCommitment<P: SchemeParams>(Vec<<P::Paillier as PaillierParams>::Uint>);

impl<P: SchemeParams> PrmCommitment<P> {
    fn new(secret: &PrmSecret<P>, base: &<P::Paillier as PaillierParams>::UintMod) -> Self {
        let commitment = secret
            .0
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
    fn new<P: SchemeParams>(
        commitment: &PrmCommitment<P>,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        // TODO (#61): generate m/8 random bytes instead and fill the vector bit by bit.
        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(commitment)
            .chain(setup)
            .chain(aux)
            .finalize_to_reader();
        let mut bytes = vec![0u8; P::SECURITY_PARAMETER];
        reader.read(&mut bytes);
        Self(bytes.iter().map(|b| b & 1 == 1).collect())
    }
}

impl Hashable for PrmChallenge {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

/**
ZK proof: Ring-Pedersen parameters.

Secret inputs:
- integer $\lambda$,
- (not explicitly mentioned in the paper, but necessary to calculate the totient) primes $p$, $q$.

Public inputs:
- Setup parameters $N$, $s$, $t$ such that $N = p q$, and $s = t^\lambda \mod N$.
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn new(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillierPrecomputed<P::Paillier>,
        lambda: &RPSecret<P::Paillier>,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        let proof_secret = PrmSecret::<P>::random(rng, sk);
        let commitment = PrmCommitment::new(&proof_secret, &setup.base);

        let totient = sk.totient_nonzero();
        let challenge = PrmChallenge::new(&commitment, setup, aux);
        let proof = proof_secret
            .0
            .iter()
            .zip(challenge.0.iter())
            .map(|(a, e)| {
                let x = a.add_mod(lambda.as_ref(), &totient);
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
    pub fn verify(&self, setup: &RPParamsMod<P::Paillier>, aux: &impl Hashable) -> bool {
        let precomputed = setup.public_key().precomputed_modulus();

        let challenge = PrmChallenge::new(&self.commitment, setup, aux);
        if challenge != self.challenge {
            return false;
        }

        for i in 0..challenge.0.len() {
            let z = self.proof[i];
            let e = challenge.0[i];
            let a = self.commitment.0[i].to_mod(precomputed);
            let pwr = setup.base.pow_bounded(&z);
            let test = if e { pwr == a * setup.power } else { pwr == a };
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

        let lambda = RPSecret::random(&mut OsRng, &sk);
        let setup = RPParamsMod::random_with_secret(&mut OsRng, &lambda, pk);

        let aux: &[u8] = b"abcde";

        let proof = PrmProof::<Params>::new(&mut OsRng, &sk, &lambda, &setup, &aux);
        assert!(proof.verify(&setup, &aux));
    }
}
