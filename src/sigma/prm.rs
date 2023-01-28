//! ZKP of Ring-Pedersen parameters ($\Pi_{prm}$, Section 6.4, Fig. 17).
//!
//! Publish $(N, s, t)$ and prove that we know a secret $\lambda$ such that
//! $s = t^\lambda \mod N$.

use crypto_bigint::{AddMod, Pow, Zero};
use rand_core::{CryptoRng, RngCore};

use crate::paillier::{PaillierParams, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::hashing::{Chain, Hashable, XOFHash};

/// Secret data the proof is based on (~ signing key)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrmProofSecret<P: PaillierParams> {
    public_key: PublicKeyPaillier<P>,
    /// `a_i`
    secret: Vec<P::FieldElement>,
}

impl<P: PaillierParams> PrmProofSecret<P> {
    pub(crate) fn random(
        rng: &mut (impl RngCore + CryptoRng),
        sk: &SecretKeyPaillier<P>,
        m: usize,
    ) -> Self {
        let secret = (0..m).map(|_| sk.random_exponent(rng)).collect::<Vec<_>>();
        Self {
            public_key: sk.public_key(),
            secret,
        }
    }

    /// `A_i`
    pub(crate) fn commitment(&self, t: &P::GroupElement) -> PrmCommitment<P> {
        let commitment = self.secret.iter().map(|a| t.pow(a)).collect();
        PrmCommitment(commitment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrmCommitment<P: PaillierParams>(Vec<P::GroupElement>);

impl<C: Chain, P: PaillierParams> Hashable<C> for PrmCommitment<P> {
    fn chain(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrmChallenge(Vec<bool>);

impl PrmChallenge {
    fn new<P: PaillierParams>(
        aux: &impl Hashable<XOFHash>,
        public: &P::GroupElement,
        commitment: &PrmCommitment<P>,
        m: usize,
    ) -> Self {
        // TODO: generate m/8 random bytes instead and fill the vector bit by bit.
        // CHECK: should we use an actual RNG here instead of variable-sized hash?
        let bytes = XOFHash::new_with_dst(b"prm-challenge")
            .chain(aux)
            .chain(public)
            .chain(commitment)
            .finalize_boxed(m);
        Self(bytes.as_ref().iter().map(|b| b & 1 == 1).collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrmProof<P: PaillierParams>(Vec<P::FieldElement>);

impl<P: PaillierParams> PrmProof<P> {
    /// Create a proof that we know the `secret`.
    pub(crate) fn new(
        proof_secret: &PrmProofSecret<P>,
        secret: &P::FieldElement,
        challenge: &PrmChallenge,
        sk: &SecretKeyPaillier<P>,
    ) -> Self {
        let totient = sk.totient();
        let zero = P::FieldElement::ZERO;
        let z = proof_secret
            .secret
            .iter()
            .zip(challenge.0.iter())
            .map(|(a, e)| a.add_mod(if *e { secret } else { &zero }, &totient))
            .collect();
        Self(z)
    }

    /// Verify that the proof is correct for a secret corresponding to the given `public`.
    pub(crate) fn verify(
        &self,
        base: &P::GroupElement,
        commitment: &PrmCommitment<P>,
        challenge: &PrmChallenge,
        public: &P::GroupElement,
    ) -> bool {
        for i in 0..challenge.0.len() {
            let z = self.0[i];
            let e = challenge.0[i];
            let a = commitment.0[i].clone();
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

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{PrmChallenge, PrmProof, PrmProofSecret};
    use crate::paillier::{PaillierTest, SecretKeyPaillier};

    #[test]
    fn protocol() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();
        let m = 10;

        let base = pk.random_group_elem(&mut OsRng);
        let secret = sk.random_field_elem(&mut OsRng);
        let public = base.pow(&secret);

        let aux: &[u8] = b"abcde";

        let proof_secret = PrmProofSecret::random(&mut OsRng, &sk, m);
        let commitment = proof_secret.commitment(&base);
        let challenge = PrmChallenge::new(&aux, &public, &commitment, m);
        let proof = PrmProof::new(&proof_secret, &secret, &challenge, &sk);
        assert!(proof.verify(&base, &commitment, &challenge, &public));
    }
}
