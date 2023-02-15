//! Proof of Paillier-Blum modulus ($\Pi_{mod}$, Fig. 16)

use crypto_bigint::{modular::Retrieve, Pow};
use rand_core::{CryptoRng, RngCore};

use crate::paillier::{PaillierParams, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::{
    hashing::{Chain, Hashable, XofHash},
    jacobi::{JacobiSymbol, JacobiSymbolTrait},
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModCommitment<P: PaillierParams>(P::FieldElement);

impl<P: PaillierParams> ModCommitment<P> {
    pub fn random(rng: &mut (impl RngCore + CryptoRng), pk: &PublicKeyPaillier<P>) -> Self {
        let w = loop {
            let w = pk.random_group_elem_raw(rng);
            if P::FieldElement::jacobi_symbol(&w, &pk.modulus()) == JacobiSymbol::MinusOne {
                break w;
            }
        };
        Self(w)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModChallenge<P: PaillierParams>(Vec<P::FieldElement>);

impl<P: PaillierParams> ModChallenge<P> {
    fn new(aux: &impl Hashable, pk: &PublicKeyPaillier<P>, security_parameter: usize) -> Self {
        // CHECK: should we hash the modulus (N) here too?
        let digest = XofHash::new_with_dst(b"mod-challenge").chain(aux);
        let ys = pk.hash_to_group_elems_raw(digest, security_parameter);
        Self(ys)
    }

    fn security_parameter(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModProofElem<P: PaillierParams> {
    x: P::FieldElement,
    a: bool,
    b: bool,
    z: P::FieldElement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

                let y = P::field_elem_to_group_elem(&challenge.0[i], &pk.modulus());
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
        let w = P::field_elem_to_group_elem(&self.commitment.0, &modulus);
        for (elem, y) in self.proof.iter().zip(self.challenge.0.iter()) {
            let z_m = P::field_elem_to_group_elem(&elem.z, &modulus);
            let mut y_m = P::field_elem_to_group_elem(y, &modulus);
            if z_m.pow(&modulus) != y_m {
                return false;
            }

            if elem.a {
                y_m = -y_m;
            }
            if elem.b {
                y_m = y_m * &w;
            }
            let x = P::field_elem_to_group_elem(&elem.x, &modulus);
            let x_sq = x * &x;
            let x_4 = x_sq * &x_sq;
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
