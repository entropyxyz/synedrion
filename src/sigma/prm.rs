//! ZKP of Ring-Pedersen parameters ($\Pi_{prm}$, Section 6.4, Fig. 17).
//!
//! Publish $(N, s, t)$ and prove that we know a secret $\lambda$ such that
//! $s = t^\lambda \mod N$.

use crypto_bigint::{
    modular::runtime_mod::{DynResidue},
    NonZero, RandomMod, Uint,
};
use crypto_primes::safe_prime;
use rand_core::{OsRng, RngCore};

pub struct SecretKeyPaillier<const L: usize, const L2: usize> {
    p: Uint<L>,
    q: Uint<L>,
}

pub struct PublicKeyPaillier<const L2: usize> {
    /// N
    modulus: Uint<L2>,
}

impl<const L: usize, const L2: usize> SecretKeyPaillier<L, L2>
where
    Uint<L2>: From<(Uint<L>, Uint<L>)>,
{
    pub fn random() -> Self {
        let p = safe_prime::<L>(Uint::<L>::BITS);
        let q = safe_prime::<L>(Uint::<L>::BITS);

        Self { p, q }
    }

    /// Euler's totient function of `p * q` - the number of positive integers up to `p * q`
    /// that are relatively prime to it.
    /// Since `p` and `q` are primes, returns `(p - 1) * (q - 1)`.
    pub fn totient(&self) -> Uint<L2> {
        let (hi, lo) = (self.p.wrapping_sub(&Uint::<L>::ONE))
            .mul_wide(&(self.q.wrapping_sub(&Uint::<L>::ONE)));
        (lo, hi).into()
    }

    pub fn public_key(&self) -> PublicKeyPaillier<L2> {
        let (hi, lo) = self.p.mul_wide(&self.q);
        PublicKeyPaillier::<L2> {
            modulus: (lo, hi).into(),
        }
    }
}

impl<const L2: usize> PublicKeyPaillier<L2> {
    pub fn modulus(&self) -> Uint<L2> {
        self.modulus
    }
}

/// Secret data the proof is based on (~ signing key)
pub(crate) struct PrmProofSecret<const L: usize, const L2: usize> {
    public_key: PublicKeyPaillier<L2>,
    /// `a_i`
    secret: Vec<Uint<L2>>,
}

impl<const L: usize, const L2: usize> PrmProofSecret<L, L2> {
    pub(crate) fn new(sk: &SecretKeyPaillier<L, L2>, m: usize) -> Self
    where
        Uint<L2>: From<(Uint<L>, Uint<L>)>,
    {
        let totient = NonZero::new(sk.totient()).unwrap();
        let secret = (0..m)
            .map(|_| Uint::<L2>::random_mod(&mut OsRng, &totient))
            .collect::<Vec<_>>();
        Self {
            public_key: sk.public_key(),
            secret,
        }
    }

    /// `A_i`
    pub(crate) fn commitment(&self, t: &DynResidue<L2>) -> PrmCommitment<L2> {
        let commitment = self.secret.iter().map(|a| t.pow(a)).collect::<Vec<_>>();
        PrmCommitment(commitment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrmCommitment<const L2: usize>(Vec<DynResidue<L2>>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrmChallenge(Vec<bool>);

impl PrmChallenge {
    fn new(m: usize) -> Self {
        // TODO: generate m/8 random bytes instead and fill the vector bit by bit.
        let mut bytes = vec![0u8; m];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes.into_iter().map(|b| b & 1 == 1).collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrmProof<const L: usize, const L2: usize>(Vec<Uint<L2>>);

impl<const L: usize, const L2: usize> PrmProof<L, L2> {
    /// Create a proof that we know the `secret`.
    pub(crate) fn new(
        proof_secret: &PrmProofSecret<L, L2>,
        secret: &Uint<L2>,
        challenge: &PrmChallenge,
        sk: &SecretKeyPaillier<L, L2>,
    ) -> Self
    where
        Uint<L2>: From<(Uint<L>, Uint<L>)>,
    {
        let totient = sk.totient();
        let z = proof_secret
            .secret
            .iter()
            .zip(challenge.0.iter())
            .map(|(a, e)| a.add_mod(if *e { secret } else { &Uint::<L2>::ZERO }, &totient))
            .collect();
        Self(z)
    }

    /// Verify that the proof is correct for a secret corresponding to the given `public`.
    pub(crate) fn verify(
        &self,
        base: &DynResidue<L2>,
        commitment: &PrmCommitment<L2>,
        challenge: &PrmChallenge,
        public: &DynResidue<L2>,
    ) -> bool {
        for i in 0..challenge.0.len() {
            let z = self.0[i];
            let e = challenge.0[i];
            let a = commitment.0[i];
            let test = if e {
                base.pow(&z) == a * public
            } else {
                base.pow(&z) == a
            };
            if !test {
                return false;
            }
        }
        return true;
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{
        modular::runtime_mod::{DynResidue, DynResidueParams},
        NonZero, RandomMod, U128,
    };
    use rand_core::OsRng;

    use super::{PrmChallenge, PrmProof, PrmProofSecret, SecretKeyPaillier};

    #[test]
    fn test_protocol() {
        let sk = SecretKeyPaillier::<1, 2>::random();
        let pk = sk.public_key();
        let m = 10;

        let N = pk.modulus();

        let params = DynResidueParams::new(&N);

        let t = U128::random_mod(&mut OsRng, &NonZero::new(N).unwrap());
        let secret = U128::random_mod(&mut OsRng, &NonZero::new(sk.totient()).unwrap());

        let t_m = DynResidue::new(&t, params);
        let public = t_m.pow(&secret);

        let proof_secret = PrmProofSecret::new(&sk, m);
        let commitment = proof_secret.commitment(&t_m);
        let challenge = PrmChallenge::new(m);
        let proof = PrmProof::new(&proof_secret, &secret, &challenge, &sk);
        assert!(proof.verify(&t_m, &commitment, &challenge, &public));
    }
}
