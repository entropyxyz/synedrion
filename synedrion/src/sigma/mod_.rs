//! Proof of Paillier-Blum modulus ($\Pi_{mod}$, Fig. 16)

use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::paillier::uint::{Pow, RandomMod, Retrieve, UintLike, UintModLike};
use crate::paillier::{PaillierParams, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::{
    hashing::{Chain, Hashable, XofHash},
    jacobi::{JacobiSymbol, JacobiSymbolTrait},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModCommitment<P: PaillierParams>(P::DoubleUint);

impl<P: PaillierParams> ModCommitment<P> {
    pub fn random(rng: &mut (impl RngCore + CryptoRng), pk: &PublicKeyPaillier<P>) -> Self {
        let w = loop {
            let w = P::DoubleUint::random_mod(rng, &pk.modulus());
            if w.jacobi_symbol(&pk.modulus()) == JacobiSymbol::MinusOne {
                break w;
            }
        };
        Self(w)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModChallenge<P: PaillierParams>(Vec<P::DoubleUint>);

impl<P: PaillierParams> ModChallenge<P> {
    fn new(aux: &impl Hashable, pk: &PublicKeyPaillier<P>, security_parameter: usize) -> Self {
        // CHECK: should we hash the modulus (N) here too?
        let mut reader = XofHash::new_with_dst(b"mod-challenge")
            .chain(aux)
            .finalize_reader();
        let modulus = pk.modulus();
        let ys = (0..security_parameter)
            .map(|_| P::DoubleUint::hash_into_mod(&mut reader, &modulus))
            .collect();
        Self(ys)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModProofElem<P: PaillierParams> {
    x: P::DoubleUint,
    a: bool,
    b: bool,
    z: P::DoubleUint,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "ModCommitment<P>: Serialize,
    ModChallenge<P>: Serialize"))]
#[serde(bound(deserialize = "ModCommitment<P>: for<'x> Deserialize<'x>,
    ModChallenge<P>: for<'x> Deserialize<'x>"))]
pub(crate) struct ModProof<P: PaillierParams> {
    commitment: ModCommitment<P>,
    challenge: ModChallenge<P>,
    proof: Vec<ModProofElem<P>>,
}

impl<P: PaillierParams> ModProof<P> {
    pub(crate) fn random(
        rng: &mut (impl RngCore + CryptoRng),
        sk: &SecretKeyPaillier<P>,
        aux: &impl Hashable,
        security_parameter: usize,
    ) -> Self {
        let pk = sk.public_key();
        let challenge = ModChallenge::new(aux, &pk, security_parameter);

        let commitment = ModCommitment::random(rng, &pk);

        let (c_mod_p, c_mod_q) = sk.rns_split(&commitment.0);

        let proof = (0..security_parameter)
            .map(|i| {
                let mut y_sqrt = None;
                let mut found_a = false;
                let mut found_b = false;
                for (a, b) in [(false, false), (false, true), (true, false), (true, true)].iter() {
                    let y = challenge.0[i];
                    let (mut y_mod_p, mut y_mod_q) = sk.rns_split(&y);
                    if *a {
                        y_mod_p = -y_mod_p;
                        y_mod_q = -y_mod_q;
                    }
                    if *b {
                        y_mod_p = y_mod_p * c_mod_p;
                        y_mod_q = y_mod_q * c_mod_q;
                    }

                    if let Some((p, q)) = sk.sqrt(&(y_mod_p, y_mod_q)) {
                        y_sqrt = Some((p, q));
                        found_a = *a;
                        found_b = *b;
                    }
                }

                let y_sqrt = y_sqrt.unwrap();

                let y_4th_parts = sk.sqrt(&y_sqrt).unwrap();
                let y_4th = sk.rns_join(&y_4th_parts);

                let y = P::DoubleUintMod::new(&challenge.0[i], &pk.modulus());
                let z = y.pow(&sk.inv_modulus());

                ModProofElem {
                    x: y_4th,
                    a: found_a,
                    b: found_b,
                    z: z.retrieve(),
                }
            })
            .collect();

        Self {
            commitment,
            challenge,
            proof,
        }
    }

    /// Verify that the proof is correct for a secret corresponding to the given `public`.
    pub(crate) fn verify(&self, pk: &PublicKeyPaillier<P>, aux: &impl Hashable) -> bool {
        let challenge = ModChallenge::new(aux, pk, self.proof.len());
        if challenge != self.challenge {
            return false;
        }

        let modulus = pk.modulus();
        let w = P::DoubleUintMod::new(&self.commitment.0, &modulus);
        for (elem, y) in self.proof.iter().zip(self.challenge.0.iter()) {
            let z_m = P::DoubleUintMod::new(&elem.z, &modulus);
            let mut y_m = P::DoubleUintMod::new(y, &modulus);
            if z_m.pow(modulus.as_ref()) != y_m {
                return false;
            }

            if elem.a {
                y_m = -y_m;
            }
            if elem.b {
                y_m = y_m * w;
            }
            let x = P::DoubleUintMod::new(&elem.x, &modulus);
            let x_sq = x * x; // TODO: use `square()` when available
            let x_4 = x_sq * x_sq; // TODO: use `square()` when available
            if y_m != x_4 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::ModProof;
    use crate::paillier::{PaillierTest, SecretKeyPaillier};

    #[test]
    fn protocol() {
        let sk = SecretKeyPaillier::<PaillierTest>::random(&mut OsRng);
        let pk = sk.public_key();
        let security_parameter = 10;

        let aux: &[u8] = b"abcde";

        let proof = ModProof::random(&mut OsRng, &sk, &aux, security_parameter);
        assert!(proof.verify(&pk, &aux));
    }
}
