//! Knowledge of Exponent vs Paillier Encryption ($\Pi^{log*}$, Section C.2, Fig. 25)

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

const HASH_TAG: &[u8] = b"P_log*";

pub(crate) struct LogStarSecretInputs<'a, P: SchemeParams> {
    /// $x \in \pm 2^\ell$.
    pub x: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $\rho$, a Paillier randomizer for the public key $N_0$.
    pub rho: &'a Randomizer<P::Paillier>,
}

pub(crate) struct LogStarPublicInputs<'a, P: SchemeParams> {
    /// Paillier public key $N_0$.
    pub pk0: &'a PublicKeyPaillier<P::Paillier>,
    /// Paillier ciphertext $C = enc_0(x, \rho)$.
    pub cap_c: &'a Ciphertext<P::Paillier>,
    /// Point $g$.
    pub g: &'a Point<P>,
    /// Point $X = g * x$.
    pub cap_x: &'a Point<P>,
}

/// ZK proof: Knowledge of Exponent vs Paillier Encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "for<'x> P: Deserialize<'x>"))]
pub(crate) struct LogStarProof<P: SchemeParams> {
    e: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    cap_s: RPCommitmentWire<P::Paillier>,
    cap_a: CiphertextWire<P::Paillier>,
    cap_y: Point<P>,
    cap_d: RPCommitmentWire<P::Paillier>,
    z1: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    z2: MaskedRandomizer<P::Paillier>,
    z3: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
}

impl<P: SchemeParams> LogStarProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: LogStarSecretInputs<'_, P>,
        public: LogStarPublicInputs<'_, P>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        secret.x.assert_exponent_range(P::L_BOUND);
        assert_eq!(public.cap_c.public_key(), public.pk0);

        let hat_cap_n = setup.modulus(); // $\hat{N}$

        let alpha = SecretSigned::random_in_exp_range(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND, hat_cap_n);
        let r = Randomizer::random(rng, public.pk0);
        let gamma = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let cap_s = setup.commit(secret.x, &mu).to_wire();
        let cap_a = Ciphertext::new_with_randomizer_signed(public.pk0, &alpha, &r).to_wire();
        let cap_y = public.g * secret_scalar_from_signed::<P>(&alpha);
        let cap_d = setup.commit(&alpha, &gamma).to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_s)
            .chain(&cap_a)
            .chain(&cap_y)
            .chain(&cap_d)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(public.g)
            .chain(public.cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = (alpha + secret.x * e).to_public();
        let z2 = secret.rho.to_masked(&r, &e);
        let z3 = (gamma + mu * e.to_wide()).to_public();

        Self {
            e,
            cap_s,
            cap_a,
            cap_y,
            cap_d,
            z1,
            z2,
            z3,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        public: LogStarPublicInputs<'_, P>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(public.cap_c.public_key(), public.pk0);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_s)
            .chain(&self.cap_a)
            .chain(&self.cap_y)
            .chain(&self.cap_d)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(public.g)
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

        // enc_0(z1, z2) == A (+) C (*) e
        let c = Ciphertext::new_public_with_randomizer_signed(public.pk0, &self.z1, &self.z2);
        if c != self.cap_a.to_precomputed(public.pk0) + public.cap_c * &e {
            return false;
        }

        // g^{z_1} == Y X^e
        if public.g * &scalar_from_signed::<P>(&self.z1) != self.cap_y + public.cap_x * &scalar_from_signed::<P>(&e) {
            return false;
        }

        // s^{z_1} t^{z_3} == D S^e \mod \hat{N}
        let cap_d = self.cap_d.to_precomputed(setup);
        let cap_s = self.cap_s.to_precomputed(setup);
        if setup.commit(&self.z1, &self.z3) != &cap_d * &cap_s.pow(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{LogStarProof, LogStarPublicInputs, LogStarSecretInputs};
    use crate::{
        cggmp21::{conversion::secret_scalar_from_signed, SchemeParams, TestParams},
        curve::{Point, Scalar},
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

        let g = Point::generator() * Scalar::random(&mut OsRng);
        let x = SecretSigned::random_in_exp_range(&mut OsRng, Params::L_BOUND);
        let rho = Randomizer::random(&mut OsRng, pk);
        let cap_c = Ciphertext::new_with_randomizer_signed(pk, &x, &rho);
        let cap_x = g * secret_scalar_from_signed::<Params>(&x);

        let proof = LogStarProof::<Params>::new(
            &mut OsRng,
            LogStarSecretInputs { x: &x, rho: &rho },
            LogStarPublicInputs {
                pk0: pk,
                cap_c: &cap_c,
                g: &g,
                cap_x: &cap_x,
            },
            &setup,
            &aux,
        );
        assert!(proof.verify(
            LogStarPublicInputs {
                pk0: pk,
                cap_c: &cap_c,
                g: &g,
                cap_x: &cap_x
            },
            &setup,
            &aux
        ));
    }
}
