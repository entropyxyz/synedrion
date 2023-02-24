//! ZKP of Ring-Pedersen parameters ($\Pi_{prm}$, Section 6.4, Fig. 17).
//!
//! Publish $(N, s, t)$ and prove that we know a secret $\lambda$ such that
//! $s = t^\lambda \mod N$.

use crypto_bigint::{AddMod, Pow, Zero};
use rand_core::{CryptoRng, RngCore};

use crate::paillier::{PaillierParams, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::hashing::{Chain, Hashable, XofHash};

/// Secret data the proof is based on (~ signing key)
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrmSecret<P: PaillierParams> {
    public_key: PublicKeyPaillier<P>,
    /// `a_i`
    secret: Vec<P::FieldElement>,
}

impl<P: PaillierParams> PrmSecret<P> {
    pub(crate) fn random(
        rng: &mut (impl RngCore + CryptoRng),
        sk: &SecretKeyPaillier<P>,
        security_parameter: usize,
    ) -> Self {
        let secret = (0..security_parameter)
            .map(|_| sk.random_exponent(rng))
            .collect::<Vec<_>>();
        Self {
            public_key: sk.public_key(),
            secret,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrmCommitment<P: PaillierParams>(Vec<P::GroupElement>);

impl<P: PaillierParams> PrmCommitment<P> {
    pub(crate) fn new(secret: &PrmSecret<P>, base: &P::GroupElement) -> Self {
        let commitment = secret.secret.iter().map(|a| base.pow(a)).collect();
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrmChallenge(Vec<bool>);

impl PrmChallenge {
    fn new<P: PaillierParams>(
        aux: &impl Hashable,
        public: &P::GroupElement,
        commitment: &PrmCommitment<P>,
    ) -> Self {
        // TODO: generate m/8 random bytes instead and fill the vector bit by bit.
        // CHECK: should we use an actual RNG here instead of variable-sized hash?
        let bytes = XofHash::new_with_dst(b"prm-challenge")
            .chain(aux)
            .chain(public)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrmProof<P: PaillierParams> {
    commitment: PrmCommitment<P>,
    challenge: PrmChallenge,
    proof: Vec<P::FieldElement>,
}

impl<P: PaillierParams> PrmProof<P> {
    /// Create a proof that we know the `secret`.
    pub(crate) fn random(
        rng: &mut (impl RngCore + CryptoRng),
        sk: &SecretKeyPaillier<P>,
        secret: &P::FieldElement,
        base: &P::GroupElement,
        public: &P::GroupElement,
        aux: &impl Hashable,
        security_parameter: usize,
    ) -> Self {
        let proof_secret = PrmSecret::random(rng, sk, security_parameter);
        let commitment = PrmCommitment::new(&proof_secret, base);

        let totient = sk.totient();
        let zero = P::FieldElement::ZERO;
        let challenge = PrmChallenge::new(aux, public, &commitment);
        let proof = proof_secret
            .secret
            .iter()
            .zip(challenge.0.iter())
            .map(|(a, e)| a.add_mod(if *e { secret } else { &zero }, &totient))
            .collect();
        Self {
            commitment,
            proof,
            challenge,
        }
    }

    /// Verify that the proof is correct for a secret corresponding to the given `public`.
    pub(crate) fn verify(
        &self,
        base: &P::GroupElement,
        public: &P::GroupElement,
        aux: &impl Hashable,
    ) -> bool {
        let challenge = PrmChallenge::new(aux, public, &self.commitment);
        if challenge != self.challenge {
            return false;
        }

        for i in 0..challenge.0.len() {
            let z = self.proof[i];
            let e = challenge.0[i];
            let a = self.commitment.0[i];
            let test = if e {
                base.pow(&z) == a * public
            } else {
                base.pow(&z) == a
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
    use crate::paillier::{PaillierTest, SecretKeyPaillier};

    #[test]
    fn protocol() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();
        let security_parameter = 10;

        let base = pk.random_group_elem(&mut OsRng);
        let secret = sk.random_field_elem(&mut OsRng);
        let public = base.pow(&secret);

        let aux: &[u8] = b"abcde";

        let proof = PrmProof::random(
            &mut OsRng,
            &sk,
            &secret,
            &base,
            &public,
            &aux,
            security_parameter,
        );
        assert!(proof.verify(&base, &public, &aux));
    }
}