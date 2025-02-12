//! Multiplication Paillier vs Group ($\Pi^{mul}$, Section C.6, Fig. 31)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    conversion::{scalar_from_signed, secret_scalar_from_signed},
    SchemeParams,
};
use crate::{
    curve::Point,
    paillier::{
        Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams,
        Randomizer,
    },
    tools::hashing::{Chain, Hashable, XofHasher},
    uint::{PublicSigned, SecretSigned},
};

const HASH_TAG: &[u8] = b"P_mul*";

pub(crate) struct MulStarSecretInputs<'a, P: SchemeParams> {
    /// $x \in +- 2^\ell$.
    pub x: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $\rho$, a Paillier randomizer for the public key $N_0$.
    pub rho: &'a Randomizer<P::Paillier>,
}

pub(crate) struct MulStarPublicInputs<'a, P: SchemeParams> {
    /// Paillier public key $N_0$.
    pub pk0: &'a PublicKeyPaillier<P::Paillier>,
    /// Paillier ciphertext $C$ encrypted with $N_0$.
    pub cap_c: &'a Ciphertext<P::Paillier>,
    /// Paillier ciphertext $D = (C (*) x) * \rho^{N_0} \mod N_0^2$.
    pub cap_d: &'a Ciphertext<P::Paillier>,
    /// Point $X = g * x$, where $g$ is the curve generator.
    pub cap_x: &'a Point<P>,
}

/// ZK proof: Multiplication Paillier vs Group.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "for<'x> P: Deserialize<'x>"))]
pub(crate) struct MulStarProof<P: SchemeParams> {
    e: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    cap_a: CiphertextWire<P::Paillier>,
    cap_b_x: Point<P>,
    cap_e: RPCommitmentWire<P::Paillier>,
    cap_s: RPCommitmentWire<P::Paillier>,
    z1: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    z2: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    omega: MaskedRandomizer<P::Paillier>,
}

impl<P: SchemeParams> MulStarProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: MulStarSecretInputs<'_, P>,
        public: MulStarPublicInputs<'_, P>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        /*
        NOTE: Several issues with the proof description in the paper:
        - the prover creates $B_x$, but sends $B$ - a typo, and they're the same thing
        - the prover creates $r_y$, but it is unused - a typo
        - $\beta$ used to create $A$ is not mentioned anywhere else - a typo, it is effectively == 0
        */

        secret.x.assert_exponent_range(P::L_BOUND);
        assert_eq!(public.cap_c.public_key(), public.pk0);
        assert_eq!(public.cap_d.public_key(), public.pk0);

        let hat_cap_n = setup.modulus(); // $\hat{N}$

        let r = Randomizer::random(rng, public.pk0);
        let alpha = SecretSigned::random_in_exp_range(rng, P::L_BOUND + P::EPS_BOUND);
        let gamma = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let m = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND, hat_cap_n);

        let cap_a = (public.cap_c * &alpha).mul_randomizer(&r).to_wire();
        let cap_b_x = secret_scalar_from_signed::<P>(&alpha).mul_by_generator();
        let cap_e = setup.commit(&alpha, &gamma).to_wire();
        let cap_s = setup.commit(secret.x, &m).to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_a)
            .chain(&cap_b_x)
            .chain(&cap_e)
            .chain(&cap_s)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(&public.cap_d.to_wire())
            .chain(public.cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = (alpha + secret.x * e).to_public();
        let z2 = (gamma + m * e.to_wide()).to_public();
        let omega = secret.rho.to_masked(&r, &e);

        Self {
            e,
            cap_a,
            cap_b_x,
            cap_e,
            cap_s,
            z1,
            z2,
            omega,
        }
    }

    #[allow(dead_code)] // TODO (#43): this can be removed when error verification is added
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        public: MulStarPublicInputs<'_, P>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(public.cap_c.public_key(), public.pk0);
        assert_eq!(public.cap_d.public_key(), public.pk0);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_a)
            .chain(&self.cap_b_x)
            .chain(&self.cap_e)
            .chain(&self.cap_s)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(&public.cap_d.to_wire())
            .chain(public.cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // Range check
        if !self.z1.in_range_bits(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        // C (*) z_1 * \omega^{N_0} == A (+) D (*) e
        if (public.cap_c * &self.z1).mul_masked_randomizer(&self.omega)
            != self.cap_a.to_precomputed(public.pk0) + public.cap_d * &e
        {
            return false;
        }

        // g^{z_1} == B_x X^e
        if scalar_from_signed::<P>(&self.z1).mul_by_generator()
            != self.cap_b_x + public.cap_x * &scalar_from_signed::<P>(&e)
        {
            return false;
        }

        // s^{z_1} t^{z_2} == E S^e
        let cap_e = self.cap_e.to_precomputed(setup);
        let cap_s = self.cap_s.to_precomputed(setup);
        if setup.commit(&self.z1, &self.z2) != &cap_e * &cap_s.pow(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{MulStarProof, MulStarPublicInputs, MulStarSecretInputs};
    use crate::{
        cggmp21::{conversion::secret_scalar_from_signed, SchemeParams, TestParams},
        paillier::{Ciphertext, RPParams, Randomizer, SecretKeyPaillierWire},
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

        let x = SecretSigned::random_in_exp_range(&mut OsRng, Params::L_BOUND);
        let secret = SecretSigned::random_in_exp_range(&mut OsRng, Params::L_BOUND);
        let rho = Randomizer::random(&mut OsRng, pk);
        let cap_c = Ciphertext::new_signed(&mut OsRng, pk, &secret);
        let cap_d = (&cap_c * &x).mul_randomizer(&rho);
        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        let proof = MulStarProof::<Params>::new(
            &mut OsRng,
            MulStarSecretInputs { x: &x, rho: &rho },
            MulStarPublicInputs {
                pk0: pk,
                cap_c: &cap_c,
                cap_d: &cap_d,
                cap_x: &cap_x,
            },
            &setup,
            &aux,
        );
        assert!(proof.verify(
            MulStarPublicInputs {
                pk0: pk,
                cap_c: &cap_c,
                cap_d: &cap_d,
                cap_x: &cap_x
            },
            &setup,
            &aux
        ));
    }
}
