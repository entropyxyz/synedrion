//! Proof of Paillier-Blum modulus ($\Pi^{mod}$, Fig. 12)
//!
//! N is a Paillier-Blum modulus if `gcd(N, φ(N)) = 1`, and `N = p q`
//! where `p`, `q` are primes satisfying `p, q ≡ 3 mod 4`.

use alloc::vec::Vec;

use crypto_bigint::{modular::Retrieve, Gcd, Integer, Square};
use crypto_primes::RandomPrimeWithRng;
use digest::XofReader;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::{
    paillier::{PaillierParams, PublicKeyPaillier, SecretKeyPaillier},
    tools::hashing::{Chain, Hashable, XofHasher},
    uint::{Exponentiable, IsInvertible, ToMontgomery},
};

const HASH_TAG: &[u8] = b"P_mod";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModCommitment<P: SchemeParams>(<P::Paillier as PaillierParams>::Uint);

impl<P: SchemeParams> ModCommitment<P> {
    fn random(rng: &mut impl CryptoRngCore, sk: &SecretKeyPaillier<P::Paillier>) -> Self {
        Self(sk.random_nonsquare_residue(rng))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModChallenge<P: SchemeParams>(Vec<<P::Paillier as PaillierParams>::Uint>);

impl<P: SchemeParams> ModChallenge<P> {
    fn new(pk: &PublicKeyPaillier<P::Paillier>, commitment: &ModCommitment<P>, aux: &impl Hashable) -> Self {
        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            .chain(pk.as_wire())
            .chain(commitment)
            .chain(aux)
            .finalize_to_reader();
        let ys = (0..P::SECURITY_BITS)
            .map(|_| pk.invertible_residue_from_xof_reader(&mut reader))
            .collect();
        Self(ys)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModProofElem<P: PaillierParams> {
    x: P::Uint,
    a: bool,
    b: bool,
    z: P::Uint,
}

/**
ZK proof: Proof of Paillier-Blum modulus.

Secret inputs:
- primes $p$, $q$.

Public inputs:
- Paillier public key $N = p q$,
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn new(rng: &mut impl CryptoRngCore, sk: &SecretKeyPaillier<P::Paillier>, aux: &impl Hashable) -> Self {
        let pk = sk.public_key();
        let commitment = ModCommitment::<P>::random(rng, sk);
        let challenge = ModChallenge::<P>::new(pk, &commitment, aux);

        let (w_mod_p, w_mod_q) = sk.rns_split(&commitment.0);

        let proof = challenge
            .0
            .iter()
            .map(|y| {
                let mut y_sqrt = None;
                let mut found_a = false;
                let mut found_b = false;
                for (a, b) in [(false, false), (false, true), (true, false), (true, true)].iter() {
                    let (mut y_mod_p, mut y_mod_q) = sk.rns_split(y);
                    if *a {
                        y_mod_p = -y_mod_p;
                        y_mod_q = -y_mod_q;
                    }
                    if *b {
                        y_mod_p *= w_mod_p.clone();
                        y_mod_q *= w_mod_q.clone();
                    }

                    if let Some((p, q)) = sk.rns_sqrt(&(y_mod_p, y_mod_q)) {
                        y_sqrt = Some((p, q));
                        found_a = *a;
                        found_b = *b;
                    }
                }

                // If N is a Paillier-Blum modulus, that is N = pq where p, q are safe primes,
                // and the commitment was sampled correctly (a non-square modulo N),
                // these square roots will exist.
                let y_sqrt = y_sqrt.expect("the square root exists if N is a Paillier-Blum modulus");
                let y_4th_parts = sk
                    .rns_sqrt(&y_sqrt)
                    .expect("the square root exists if N is a Paillier-Blum modulus");

                let y_4th = sk.rns_join(&y_4th_parts);

                let y = y.to_montgomery(pk.monty_params_mod_n());
                let sk_inv_modulus = sk.inv_modulus();
                let z = y.pow(sk_inv_modulus);

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

    pub fn verify(&self, pk: &PublicKeyPaillier<P::Paillier>, aux: &impl Hashable) -> bool {
        let challenge = ModChallenge::new(pk, &self.commitment, aux);
        if challenge != self.challenge {
            return false;
        }

        let mut reader = XofHasher::new_with_dst(b"P_mod RNG")
            // commitments
            .chain(&self.commitment)
            // public parameters
            .chain(pk.as_wire())
            .chain(aux)
            .finalize_to_reader();
        let mut seed = <ChaCha12Rng as SeedableRng>::Seed::default();
        reader.read(&mut seed);
        let mut rng = ChaCha12Rng::from_seed(seed);

        // The paper requires checking that `N` is odd and composite here,
        // but being odd is already an invariant of `PublicKeyPaillier`.
        if (*pk.modulus()).is_prime_with_rng(&mut rng) {
            return false;
        }

        if pk.modulus().gcd(&self.commitment.0) != <P::Paillier as PaillierParams>::Uint::one() {
            return false;
        }

        let pk_modulus = pk.modulus_signed();

        let monty_params = pk.monty_params_mod_n();
        let w_mod = self.commitment.0.to_montgomery(monty_params);
        for (elem, y) in self.proof.iter().zip(self.challenge.0.iter()) {
            let z_m = elem.z.to_montgomery(monty_params);
            let mut y_m = y.to_montgomery(monty_params);

            // Check if $y_i ∈ Z^*_N$.
            if !y.is_invertible(pk.modulus()) {
                return false;
            }

            if z_m.pow(&pk_modulus) != y_m {
                return false;
            }

            if elem.a {
                y_m = -y_m;
            }
            if elem.b {
                y_m *= w_mod;
            }
            let x = elem.x.to_montgomery(monty_params);
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
    use manul::{dev::BinaryFormat, session::WireFormat};
    use rand_core::OsRng;

    use super::ModProof;
    use crate::{cggmp21::SchemeParams, dev::TestParams, paillier::SecretKeyPaillierWire};

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let aux: &[u8] = b"abcde";

        let proof = ModProof::<Params>::new(&mut OsRng, &sk, &aux);

        // Serialization roundtrip
        let serialized = BinaryFormat::serialize(proof).unwrap();
        let proof = BinaryFormat::deserialize::<ModProof<Params>>(&serialized).unwrap();

        assert!(proof.verify(pk, &aux));
    }
}
