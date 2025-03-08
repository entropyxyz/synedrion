//! Paillier Special Decryption in the Exponent ($\Pi^{dec}$, Section A.6, Fig. 28)

use alloc::{boxed::Box, vec::Vec};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    conversion::{
        scalar_from_signed, scalar_from_wide_signed, secret_scalar_from_signed, secret_scalar_from_wide_signed,
    },
    SchemeParams,
};
use crate::{
    curve::Point,
    paillier::{Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, RPParams, Randomizer},
    tools::{
        bitvec::BitVec,
        hashing::{Chain, Hashable, XofHasher},
    },
    uint::{PublicSigned, SecretSigned},
};

const HASH_TAG: &[u8] = b"P_dec";

pub(crate) struct DecSecretInputs<'a, P: SchemeParams> {
    /// $x ∈ \mathbb{I}$, that is $x ∈ ±2^\ell$ (see N.B. just before Section 4.1)
    pub x: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    // DEVIATION FROM THE PAPER.
    // The paper requires $y ∈ \mathbb{J}$, that is $y ∈ ±2^{\ell^\prime}$,
    // but the actual argument we use in the error rounds has a wider expected range.
    /// $y ∈ ±2^{\ell^\prime + \eps + 1 + ceil(log2(num_parties))}$.
    pub y: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $\rho$, a Paillier randomizer for the public key $N_0$.
    pub rho: &'a Randomizer<P::Paillier>,
}

pub(crate) struct DecPublicInputs<'a, P: SchemeParams> {
    /// Paillier public key $N_0$.
    pub pk0: &'a PublicKeyPaillier<P::Paillier>,
    /// Paillier ciphertext $K$ such that $enc_0(y, \rho) = K (*) x (+) D$.
    // DEVIATION FROM THE PAPER.
    // Fig. 28 says `enc_0(z, \rho) = ...` which is a typo.
    pub cap_k: &'a Ciphertext<P::Paillier>,
    /// Point $X = g^x$, where $g$ is the curve generator.
    pub cap_x: &'a Point<P>,
    /// Paillier ciphertext $D$, see the doc for `cap_k` above.
    pub cap_d: &'a Ciphertext<P::Paillier>,
    /// Point $S = G^y$.
    pub cap_s: &'a Point<P>,
    /// The base point $G$.
    // DEVIATION FROM THE PAPER.
    // In Fig. 28 it is not mentioned in the list of parameters and taken to be $g$.
    // But it is explicitly mentioned in Fig. 8 and 9, and the ZK proof in the error round
    // (for $\hat{D}$ and $\hat{F}$) uses a value different from $g$.
    pub cap_g: &'a Point<P>,
    // DEVIATION FROM THE PAPER.
    // The number of parties we need for the modified range check, see the comment for `DecSecretInputs::y`.
    pub num_parties: usize,
}

/// ZK proof: Paillier decryption modulo $q$.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    DecProofCommitment<P>: Serialize,
    DecProofElement<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    DecProofCommitment<P>: for<'x> Deserialize<'x>,
    DecProofElement<P>: for<'x> Deserialize<'x>
"))]
pub(crate) struct DecProof<P: SchemeParams> {
    e: BitVec,
    commitments: Box<[DecProofCommitment<P>]>,
    elements: Box<[DecProofElement<P>]>,
}

struct DecProofEphemeral<P: SchemeParams> {
    alpha: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    beta: SecretSigned<<P::Paillier as PaillierParams>::WideUint>,
    r: Randomizer<P::Paillier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "Point<P>: for<'x> Deserialize<'x>,"))]
pub(crate) struct DecProofCommitment<P: SchemeParams> {
    cap_a: CiphertextWire<P::Paillier>,
    cap_b: Point<P>,
    cap_c: Point<P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DecProofElement<P: SchemeParams> {
    z: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    w: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    nu: MaskedRandomizer<P::Paillier>,
}

impl<P: SchemeParams> DecProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: DecSecretInputs<'_, P>,
        public: DecPublicInputs<'_, P>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        secret.x.assert_exponent_range(P::L_BOUND);

        // DEVIATION FROM THE PAPER.
        // The expected range of `y` is extended, see the comment for `DecSecretInputs::y`.
        let ceil_log2_num_parties = (public.num_parties - 1).ilog2() + 1;
        let y_bound = P::LP_BOUND + P::EPS_BOUND + 1 + ceil_log2_num_parties;
        secret.y.assert_exponent_range(y_bound);

        assert_eq!(public.cap_k.public_key(), public.pk0);
        assert_eq!(public.cap_d.public_key(), public.pk0);

        let (ephemerals, commitments): (Vec<_>, Vec<_>) = (0..P::SECURITY_PARAMETER)
            .map(|_| {
                let alpha = SecretSigned::random_in_exponent_range(rng, P::L_BOUND + P::EPS_BOUND);
                let beta = SecretSigned::<<P::Paillier as PaillierParams>::WideUint>::random_in_exponent_range(
                    rng,
                    y_bound + P::EPS_BOUND,
                );
                let r = Randomizer::random(rng, public.pk0);

                let cap_a =
                    (public.cap_k * &-&alpha + Ciphertext::new_wide_with_randomizer(public.pk0, &beta, &r)).to_wire();

                // DEVIATION FROM THE PAPER.
                // See the comment in `DecPublicInputs`.
                // Using the public `G` point instead of the generator.
                let cap_b = public.cap_g * secret_scalar_from_wide_signed::<P>(&beta);
                let cap_c = secret_scalar_from_signed::<P>(&alpha).mul_by_generator();

                let ephemeral = DecProofEphemeral::<P> { alpha, beta, r };
                let commitment = DecProofCommitment { cap_a, cap_b, cap_c };

                (ephemeral, commitment)
            })
            .unzip();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&commitments)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_k.to_wire())
            .chain(&public.cap_x)
            .chain(&public.cap_d.to_wire())
            .chain(&public.cap_s)
            .chain(&public.cap_g)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = BitVec::from_xof_reader(&mut reader, P::SECURITY_PARAMETER);

        let elements = ephemerals
            .into_iter()
            .zip(e.bits())
            .map(|(ephemeral, e_bit)| {
                let DecProofEphemeral { alpha, beta, r } = ephemeral;

                let z = if *e_bit { alpha + secret.x } else { alpha };
                let w = if *e_bit { beta + secret.y.to_wide() } else { beta };

                let exponent = if *e_bit {
                    PublicSigned::one()
                } else {
                    PublicSigned::zero()
                };
                let nu = secret.rho.to_masked(&r, &exponent);

                DecProofElement {
                    z: z.to_public(),
                    w: w.to_public(),
                    nu,
                }
            })
            .collect::<Vec<_>>();

        Self {
            e,
            elements: elements.into(),
            commitments: commitments.into(),
        }
    }

    pub fn verify(&self, public: DecPublicInputs<'_, P>, setup: &RPParams<P::Paillier>, aux: &impl Hashable) -> bool {
        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.commitments)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_k.to_wire())
            .chain(&public.cap_x)
            .chain(&public.cap_d.to_wire())
            .chain(&public.cap_s)
            .chain(&public.cap_g)
            .chain(&setup.to_wire())
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
            // enc(w_j, \nu_j) (+) K (*) (-z_j) == A_j (+) D (*) e_j
            let cap_a = commitment.cap_a.to_precomputed(public.pk0);
            let lhs = Ciphertext::new_public_wide_with_randomizer(public.pk0, &element.w, &element.nu)
                + public.cap_k * &-element.z;
            let rhs = if e_bit { cap_a + public.cap_d } else { cap_a };
            if lhs != rhs {
                return false;
            }

            // g^z_j == C_j X^{e_j}
            let lhs = scalar_from_signed::<P>(&element.z).mul_by_generator();
            let rhs = if e_bit {
                commitment.cap_c + *public.cap_x
            } else {
                commitment.cap_c
            };
            if lhs != rhs {
                return false;
            }

            // DEVIATION FROM THE PAPER.
            // See the comment in `DecPublicInputs`.
            // Using the public `G` point instead of the generator, so the condition is now `G^{w_j} == B_j S^{e_j}`.
            let lhs = public.cap_g * scalar_from_wide_signed::<P>(&element.w);
            let rhs = if e_bit {
                commitment.cap_b + *public.cap_s
            } else {
                commitment.cap_b
            };
            if lhs != rhs {
                return false;
            }

            // Range checks.

            if !element.z.is_in_exponent_range(P::L_BOUND + P::EPS_BOUND) {
                return false;
            }

            // DEVIATION FROM THE PAPER.
            // The expected range of `y` is extended, see the comment for `DecSecretInputs::y`.
            let ceil_log2_num_parties = (public.num_parties - 1).ilog2() + 1;
            if !element
                .w
                .is_in_exponent_range(P::LP_BOUND + P::EPS_BOUND + 1 + ceil_log2_num_parties + P::EPS_BOUND)
            {
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

    use super::{DecProof, DecPublicInputs, DecSecretInputs};
    use crate::{
        cggmp21::{conversion::secret_scalar_from_signed, SchemeParams, TestParams},
        curve::Scalar,
        paillier::{Ciphertext, PaillierParams, RPParams, Randomizer, SecretKeyPaillierWire},
        uint::SecretSigned,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let setup = RPParams::random(&mut OsRng);

        let aux: &[u8] = b"abcde";

        let num_parties: usize = 10;
        let ceil_log2_num_parties = (num_parties - 1).ilog2() + 1;

        let x = SecretSigned::random_in_exponent_range(&mut OsRng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(
            &mut OsRng,
            Params::LP_BOUND + Params::EPS_BOUND + 1 + ceil_log2_num_parties,
        );
        let rho = Randomizer::random(&mut OsRng, pk);

        // We need $enc_0(y, \rho) = K (*) x + D$,
        // so we can choose the plaintext of `K` at random, and derive the plaintext of `D`
        // (not deriving `y` since we want it to be in a specific range).

        let k = SecretSigned::random_in_exponent_range(&mut OsRng, Paillier::PRIME_BITS * 2 - 1);
        let cap_k = Ciphertext::new(&mut OsRng, pk, &k);
        let cap_d = Ciphertext::new_with_randomizer(pk, &y, &rho) + &cap_k * &-&x;

        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        let cap_g = Scalar::random(&mut OsRng).mul_by_generator();
        let cap_s = cap_g * secret_scalar_from_signed::<Params>(&y);

        let proof = DecProof::<Params>::new(
            &mut OsRng,
            DecSecretInputs {
                x: &x,
                y: &y,
                rho: &rho,
            },
            DecPublicInputs {
                pk0: pk,
                cap_k: &cap_k,
                cap_x: &cap_x,
                cap_d: &cap_d,
                cap_s: &cap_s,
                cap_g: &cap_g,
                num_parties,
            },
            &setup,
            &aux,
        );

        // Roundtrip works
        let res = BinaryFormat::serialize(proof);
        assert!(res.is_ok());
        let payload = res.unwrap();
        let proof: DecProof<Params> = BinaryFormat::deserialize(&payload).unwrap();
        let rp_params = setup.to_wire().to_precomputed();

        assert!(proof.verify(
            DecPublicInputs {
                pk0: pk,
                cap_k: &cap_k,
                cap_x: &cap_x,
                cap_d: &cap_d,
                cap_s: &cap_s,
                cap_g: &cap_g,
                num_parties,
            },
            &rp_params,
            &aux
        ));
    }
}
