//! Proof of Paillier-Blum modulus ($\Pi^{mod}$, Fig. 16)

use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{PaillierParams, PublicKeyPaillierPrecomputed, SecretKeyPaillierPrecomputed};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::{JacobiSymbol, JacobiSymbolTrait, RandomMod, Retrieve, UintLike, UintModLike};

const HASH_TAG: &[u8] = b"P_mod";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModCommitment<P: SchemeParams>(<P::Paillier as PaillierParams>::Uint);

impl<P: SchemeParams> ModCommitment<P> {
    pub fn random(
        rng: &mut impl CryptoRngCore,
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>,
    ) -> Self {
        let w = loop {
            let w = <P::Paillier as PaillierParams>::Uint::random_mod(rng, &pk.modulus_nonzero());
            if w.jacobi_symbol(pk.modulus()) == JacobiSymbol::MinusOne {
                break w;
            }
        };
        Self(w)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModChallenge<P: SchemeParams>(Vec<<P::Paillier as PaillierParams>::Uint>);

impl<P: SchemeParams> ModChallenge<P> {
    fn new(aux: &impl Hashable, pk: &PublicKeyPaillierPrecomputed<P::Paillier>) -> Self {
        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(aux)
            .finalize_to_reader();

        let modulus = pk.modulus_nonzero();
        let ys = (0..P::SECURITY_PARAMETER)
            .map(|_| <P::Paillier as PaillierParams>::Uint::from_xof(&mut reader, &modulus))
            .collect();
        Self(ys)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModProofElem<P: PaillierParams> {
    x: P::Uint,
    a: bool,
    b: bool,
    z: P::Uint,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "ModCommitment<P>: Serialize,
    ModChallenge<P>: Serialize"))]
#[serde(bound(deserialize = "ModCommitment<P>: for<'x> Deserialize<'x>,
    ModChallenge<P>: for<'x> Deserialize<'x>"))]
pub(crate) struct ModProof<P: SchemeParams> {
    commitment: ModCommitment<P>,
    challenge: ModChallenge<P>,
    proof: Vec<ModProofElem<P::Paillier>>,
}

impl<P: SchemeParams> ModProof<P> {
    pub(crate) fn random(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillierPrecomputed<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        let pk = sk.public_key();
        let challenge = ModChallenge::<P>::new(aux, pk);

        let commitment = ModCommitment::<P>::random(rng, pk);

        let (omega_mod_p, omega_mod_q) = sk.rns_split(&commitment.0);

        let proof = (0..challenge.0.len())
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
                        y_mod_p = y_mod_p * omega_mod_p;
                        y_mod_q = y_mod_q * omega_mod_q;
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

                let y = challenge.0[i].to_mod(pk.precomputed_modulus());
                let z = y.pow_bounded(sk.inv_modulus());

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

    pub(crate) fn verify(
        &self,
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        let challenge = ModChallenge::new(aux, pk);
        if challenge != self.challenge {
            return false;
        }

        let precomputed = pk.precomputed_modulus();
        let omega_mod = self.commitment.0.to_mod(precomputed);
        for (elem, y) in self.proof.iter().zip(self.challenge.0.iter()) {
            let z_m = elem.z.to_mod(precomputed);
            let mut y_m = y.to_mod(precomputed);
            if z_m.pow_bounded(&pk.modulus_bounded()) != y_m {
                return false;
            }

            if elem.a {
                y_m = -y_m;
            }
            if elem.b {
                y_m = y_m * omega_mod;
            }
            let x = elem.x.to_mod(precomputed);
            let x_4 = x.square().square();
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
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::paillier::SecretKeyPaillier;

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let aux: &[u8] = b"abcde";

        let proof = ModProof::<Params>::random(&mut OsRng, &sk, &aux);
        assert!(proof.verify(pk, &aux));
    }
}
