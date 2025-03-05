//! Setup-less Aﬃne Operation w/ Group Commitment ($\Pi^{aff-g*}$, Fig. 27)

use alloc::{boxed::Box, vec::Vec};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    conversion::{scalar_from_signed, secret_scalar_from_signed},
    SchemeParams,
};
use crate::{
    curve::Point,
    paillier::{Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, Randomizer},
    tools::{
        bitvec::BitVec,
        hashing::{Chain, Hashable, XofHasher},
    },
    uint::{PublicSigned, SecretSigned},
};

const HASH_TAG: &[u8] = b"P_aff_g*";

pub(crate) struct AffGStarSecretInputs<'a, P: SchemeParams> {
    /// $x ∈ ±2^\ell$.
    pub x: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $y ∈ ±2^{\ell^\prime}$.
    pub y: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $\rho$, a Paillier randomizer for the public key $N_0$.
    pub rho: &'a Randomizer<P::Paillier>,
    /// $\mu$, a Paillier randomizer for the public key $N_1$.
    pub mu: &'a Randomizer<P::Paillier>,
}

pub(crate) struct AffGStarPublicInputs<'a, P: SchemeParams> {
    /// Paillier public keys $N_0$.
    pub pk0: &'a PublicKeyPaillier<P::Paillier>,
    /// Paillier public keys $N_1$.
    pub pk1: &'a PublicKeyPaillier<P::Paillier>,
    /// Paillier ciphertext $C$ encrypted with $N_0$.
    pub cap_c: &'a Ciphertext<P::Paillier>,
    /// Paillier ciphertext $D = C (*) x (+) enc_0(-y, \rho)$.
    // DEVIATION FROM THE PAPER.
    // The proof in the paper assumes $D = C (*) x (+) enc_0(y, \rho)$.
    // But the way it is used in the Presigning, $D$ will actually be $... (+) enc_0(-y, \rho)$.
    // So we have to negate several variables when constructing the proof for the whole thing to work.
    pub cap_d: &'a Ciphertext<P::Paillier>,
    /// Paillier ciphertext $Y = enc_1(y, \mu)$.
    pub cap_y: &'a Ciphertext<P::Paillier>,
    /// Point $X = g^x$, where $g$ is the curve generator.
    pub cap_x: &'a Point<P>,
}

struct AffGStarProofEphemeral<P: SchemeParams> {
    alpha: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    beta: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    r: Randomizer<P::Paillier>,
    s: Randomizer<P::Paillier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "Point<P>: for<'x> Deserialize<'x>,"))]
struct AffGStarProofCommitment<P: SchemeParams> {
    cap_a: CiphertextWire<P::Paillier>,
    cap_r: Point<P>,
    cap_b: CiphertextWire<P::Paillier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AffGStarProofElement<P: SchemeParams> {
    z: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    z_prime: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    w: MaskedRandomizer<P::Paillier>,
    lambda: MaskedRandomizer<P::Paillier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    AffGStarProofCommitment<P>: Serialize,
    AffGStarProofElement<P>: Serialize,
"))]
#[serde(bound(deserialize = "AffGStarProofCommitment<P>: for<'x> Deserialize<'x>,"))]
pub(crate) struct AffGStarProof<P: SchemeParams> {
    e: BitVec,
    commitments: Box<[AffGStarProofCommitment<P>]>,
    elements: Box<[AffGStarProofElement<P>]>,
}

impl<P: SchemeParams> AffGStarProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: AffGStarSecretInputs<'_, P>,
        public: AffGStarPublicInputs<'_, P>,
        aux: &impl Hashable,
    ) -> Self {
        secret.x.assert_exponent_range(P::L_BOUND);
        secret.y.assert_exponent_range(P::LP_BOUND);
        assert!(public.cap_c.public_key() == public.pk0);
        assert!(public.cap_d.public_key() == public.pk0);
        assert!(public.cap_y.public_key() == public.pk1);

        let (ephemerals, commitments): (Vec<_>, Vec<_>) = (0..P::SECURITY_PARAMETER)
            .map(|_| {
                let alpha = SecretSigned::random_in_exponent_range(rng, P::L_BOUND + P::EPS_BOUND);
                let beta = SecretSigned::random_in_exponent_range(rng, P::LP_BOUND + P::EPS_BOUND);
                let r = Randomizer::random(rng, public.pk0);
                let s = Randomizer::random(rng, public.pk1);

                let cap_a = (public.cap_c * &alpha + Ciphertext::new_with_randomizer(public.pk0, &beta, &r)).to_wire();
                let cap_r = secret_scalar_from_signed::<P>(&alpha).mul_by_generator();
                let cap_b = Ciphertext::new_with_randomizer(public.pk1, &beta, &s).to_wire();

                let ephemeral = AffGStarProofEphemeral::<P> { alpha, beta, r, s };
                let commitment = AffGStarProofCommitment { cap_a, cap_r, cap_b };

                (ephemeral, commitment)
            })
            .unzip();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&commitments)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(public.pk1.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(&public.cap_d.to_wire())
            .chain(&public.cap_y.to_wire())
            .chain(&public.cap_x)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = BitVec::from_xof_reader(&mut reader, P::SECURITY_PARAMETER);

        let elements = ephemerals
            .into_iter()
            .zip(e.bits())
            .map(|(ephemeral, e_bit)| {
                let z = if *e_bit {
                    ephemeral.alpha + secret.x
                } else {
                    ephemeral.alpha
                };
                let z_prime = if *e_bit {
                    // DEVIATION FROM THE PAPER.
                    // See the comment in `AffGStarPublicInputs`.
                    // Original: $+ y$. Modified: $- y$
                    ephemeral.beta + secret.y.neg()
                } else {
                    ephemeral.beta
                };

                let exponent = if *e_bit {
                    PublicSigned::one()
                } else {
                    PublicSigned::zero()
                };
                let w = secret.rho.to_masked(&ephemeral.r, &exponent);
                // DEVIATION FROM THE PAPER.
                // See the comment in `AffGStarPublicInputs`.
                // Original: $\mu^{e_j}$. Modified: $\mu_{-e_j}$.
                let lambda = secret.mu.to_masked(&ephemeral.s, &-exponent);

                AffGStarProofElement {
                    z: z.to_public(),
                    z_prime: z_prime.to_public(),
                    w,
                    lambda,
                }
            })
            .collect::<Vec<_>>();

        Self {
            e,
            elements: elements.into(),
            commitments: commitments.into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(&self, public: AffGStarPublicInputs<'_, P>, aux: &impl Hashable) -> bool {
        assert!(public.cap_c.public_key() == public.pk0);
        assert!(public.cap_d.public_key() == public.pk0);
        assert!(public.cap_y.public_key() == public.pk1);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.commitments)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(public.pk1.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(&public.cap_d.to_wire())
            .chain(&public.cap_y.to_wire())
            .chain(&public.cap_x)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = BitVec::from_xof_reader(&mut reader, P::SECURITY_PARAMETER);

        if e != self.e {
            return false;
        }

        if e.bits().len() != self.commitments.len() || e.bits().len() != self.elements.len() {
            return false;
        }

        for ((e_bit, commitment), element) in e
            .bits()
            .iter()
            .copied()
            .zip(self.commitments.iter())
            .zip(self.elements.iter())
        {
            // z_j ∈ ±2^{\ell + \eps}
            if !element.z.is_in_exponent_range(P::L_BOUND + P::EPS_BOUND) {
                return false;
            }

            // z^\prime_j ∈ ±2^{\ell^\prime + \eps}
            if !element.z_prime.is_in_exponent_range(P::LP_BOUND + P::EPS_BOUND) {
                return false;
            }

            // C (*) z_j (+) enc_0(z^\prime_j, w_j) == A_j (+) D_j (*) e_j
            let cap_a = commitment.cap_a.to_precomputed(public.pk0);
            let lhs = public.cap_c * &element.z
                + Ciphertext::new_public_with_randomizer(public.pk0, &element.z_prime, &element.w);
            let rhs = if e_bit { cap_a + public.cap_d } else { cap_a };
            if lhs != rhs {
                return false;
            }

            // g^{z_j} == R_j X^{e_j}
            let lhs = scalar_from_signed::<P>(&element.z).mul_by_generator();
            let rhs = if e_bit {
                commitment.cap_r + *public.cap_x
            } else {
                commitment.cap_r
            };
            if lhs != rhs {
                return false;
            }

            // enc_1(z^\prime_j, \lambda_j) == B_j (+) Y^{-e_j}
            let cap_b = commitment.cap_b.to_precomputed(public.pk1);
            let lhs = Ciphertext::new_public_with_randomizer(public.pk1, &element.z_prime, &element.lambda);
            let rhs = if e_bit {
                // DEVIATION FROM THE PAPER.
                // See the comment in `AffGStarPublicInputs`.
                // Original: $B_j (+) Y^{e_j}$. Modified: $B_j (-) Y^{e_j}$.
                cap_b - public.cap_y
            } else {
                cap_b
            };
            if lhs != rhs {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{AffGStarProof, AffGStarPublicInputs, AffGStarSecretInputs};
    use crate::{
        cggmp21::{conversion::secret_scalar_from_signed, SchemeParams, TestParams},
        paillier::{Ciphertext, Randomizer, SecretKeyPaillierWire},
        uint::SecretSigned,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk0 = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk0 = sk0.public_key();

        let sk1 = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk1 = sk1.public_key();

        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(&mut OsRng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(&mut OsRng, Params::LP_BOUND);
        let rho = Randomizer::random(&mut OsRng, pk0);
        let mu = Randomizer::random(&mut OsRng, pk1);

        let secret = SecretSigned::random_in_exponent_range(&mut OsRng, Params::L_BOUND);
        let cap_c = Ciphertext::new(&mut OsRng, pk0, &secret);

        let cap_d = &cap_c * &x + Ciphertext::new_with_randomizer(pk0, &-&y, &rho);
        let cap_y = Ciphertext::new_with_randomizer(pk1, &y, &mu);
        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        let proof = AffGStarProof::<Params>::new(
            &mut OsRng,
            AffGStarSecretInputs {
                x: &x,
                y: &y,
                rho: &rho,
                mu: &mu,
            },
            AffGStarPublicInputs {
                pk0,
                pk1,
                cap_c: &cap_c,
                cap_d: &cap_d,
                cap_y: &cap_y,
                cap_x: &cap_x,
            },
            &aux,
        );
        assert!(proof.verify(
            AffGStarPublicInputs {
                pk0,
                pk1,
                cap_c: &cap_c,
                cap_d: &cap_d,
                cap_y: &cap_y,
                cap_x: &cap_x,
            },
            &aux
        ));
    }
}
