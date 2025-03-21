//! Paillier Affine Operation with Group Commitment in Range ($\Pi^{aff-g}$, Fig. 25)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar},
    paillier::{
        Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams,
        Randomizer,
    },
    params::{public_signed_from_scalar, scalar_from_signed, secret_scalar_from_signed, SchemeParams},
    tools::hashing::{Chain, Hashable, Hasher},
    uint::{PublicSigned, SecretSigned},
};

const HASH_TAG: &[u8] = b"P_aff_g";

pub(crate) struct AffGSecretInputs<'a, P: SchemeParams> {
    /// $x ∈ ±2^\ell$.
    pub x: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $y ∈ ±2^{\ell^\prime}$.
    pub y: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $\rho$, a Paillier randomizer for the public key $N_0$.
    pub rho: &'a Randomizer<P::Paillier>,
    /// $\rho_y$, a Paillier randomizer for the public key $N_1$.
    pub rho_y: &'a Randomizer<P::Paillier>,
}

#[derive(Clone, Copy)]
pub(crate) struct AffGPublicInputs<'a, P: SchemeParams> {
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
    /// Paillier ciphertext $Y = enc_1(y, \rho_y)$.
    pub cap_y: &'a Ciphertext<P::Paillier>,
    /// Point $X = g * x$, where $g$ is the curve generator.
    pub cap_x: &'a Point<P>,
}

/// ZK proof: Paillier Affine Operation with Group Commitment in Range.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "
    Scalar<P>: for<'x> Deserialize<'x>,
    Point<P>: for<'x> Deserialize<'x>
"))]
pub(crate) struct AffGProof<P: SchemeParams> {
    e: Scalar<P>,
    cap_a: CiphertextWire<P::Paillier>,
    cap_b_x: Point<P>,
    cap_b_y: CiphertextWire<P::Paillier>,
    cap_e: RPCommitmentWire<P::Paillier>,
    cap_s: RPCommitmentWire<P::Paillier>,
    cap_f: RPCommitmentWire<P::Paillier>,
    cap_t: RPCommitmentWire<P::Paillier>,
    z1: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    z2: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    z3: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    z4: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    w: MaskedRandomizer<P::Paillier>,
    w_y: MaskedRandomizer<P::Paillier>,
}

impl<P: SchemeParams> AffGProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: AffGSecretInputs<'_, P>,
        public: AffGPublicInputs<'_, P>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        secret.x.assert_exponent_range(P::L_BOUND);
        secret.y.assert_exponent_range(P::LP_BOUND);
        assert!(public.cap_c.public_key() == public.pk0);
        assert!(public.cap_d.public_key() == public.pk0);
        assert!(public.cap_y.public_key() == public.pk1);

        let hat_cap_n = setup.modulus();

        let alpha = SecretSigned::random_in_exponent_range(rng, P::L_BOUND + P::EPS_BOUND);
        let beta = SecretSigned::random_in_exponent_range(rng, P::LP_BOUND + P::EPS_BOUND);

        let r = Randomizer::random(rng, public.pk0);
        let r_y = Randomizer::random(rng, public.pk1);

        let gamma = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let m = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND, hat_cap_n);
        let delta = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let mu = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND, hat_cap_n);

        let cap_a = (public.cap_c * &alpha + Ciphertext::new_with_randomizer(public.pk0, &beta, &r)).to_wire();
        let cap_b_x = secret_scalar_from_signed::<P>(&alpha).mul_by_generator();
        let cap_b_y = Ciphertext::new_with_randomizer(public.pk1, &beta, &r_y).to_wire();
        let cap_e = setup.commit(&alpha, &gamma).to_wire();
        let cap_s = setup.commit(secret.x, &m).to_wire();
        let cap_f = setup.commit(&beta, &delta).to_wire();

        // DEVIATION FROM THE PAPER.
        // See the comment in `AffGPublicInputs`.
        // Original: $s^y$. Modified: $s^{-y}$
        let cap_t = setup.commit(&(-secret.y), &mu).to_wire();

        let mut reader = Hasher::<P::Digest>::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_a)
            .chain(&cap_b_x)
            .chain(&cap_b_y)
            .chain(&cap_e)
            .chain(&cap_f)
            .chain(&cap_s)
            .chain(&cap_t)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(public.pk1.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(&public.cap_d.to_wire())
            .chain(&public.cap_y.to_wire())
            .chain(public.cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e_scalar = Scalar::from_xof_reader(&mut reader);
        let e = public_signed_from_scalar::<P>(&e_scalar);
        let e_wide = e.to_wide();

        let z1 = (alpha + secret.x * e).to_public();

        // DEVIATION FROM THE PAPER.
        // See the comment in `AffGPublicInputs`.
        // Original: $z_2 = \beta + e y$
        // Modified: $z_2 = \beta - e y$
        let z2 = (beta + (-secret.y) * e).to_public();

        let z3 = (gamma + m * e_wide).to_public();
        let z4 = (delta + mu * e_wide).to_public();

        let w = secret.rho.to_masked(&r, &e);

        // DEVIATION FROM THE PAPER.
        // See the comment in `AffGPublicInputs`.
        // Original: $\rho_y^e$. Modified: $\rho_y^{-e}$.
        let w_y = secret.rho_y.to_masked(&r_y, &-e);

        Self {
            e: e_scalar,
            cap_a,
            cap_b_x,
            cap_b_y,
            cap_e,
            cap_s,
            cap_f,
            cap_t,
            z1,
            z2,
            z3,
            z4,
            w,
            w_y,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(&self, public: AffGPublicInputs<'_, P>, setup: &RPParams<P::Paillier>, aux: &impl Hashable) -> bool {
        assert!(public.cap_c.public_key() == public.pk0);
        assert!(public.cap_d.public_key() == public.pk0);
        assert!(public.cap_y.public_key() == public.pk1);

        let mut reader = Hasher::<P::Digest>::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_a)
            .chain(&self.cap_b_x)
            .chain(&self.cap_b_y)
            .chain(&self.cap_e)
            .chain(&self.cap_f)
            .chain(&self.cap_s)
            .chain(&self.cap_t)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(public.pk1.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(&public.cap_d.to_wire())
            .chain(&public.cap_y.to_wire())
            .chain(public.cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e_scalar = Scalar::from_xof_reader(&mut reader);

        if e_scalar != self.e {
            return false;
        }

        let e = public_signed_from_scalar::<P>(&e_scalar);

        // Range checks

        if !self.z1.is_in_exponent_range(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        if !self.z2.is_in_exponent_range(P::LP_BOUND + P::EPS_BOUND) {
            return false;
        }

        // C (*) z_1 (+) enc_0(z_2, w) == A (+) D (*) e
        if public.cap_c * &self.z1 + Ciphertext::new_public_with_randomizer(public.pk0, &self.z2, &self.w)
            != public.cap_d * &e + self.cap_a.to_precomputed(public.pk0)
        {
            return false;
        }

        // g^{z_1} == B_x X^e
        if scalar_from_signed::<P>(&self.z1).mul_by_generator() != self.cap_b_x + public.cap_x * e_scalar {
            return false;
        }

        // DEVIATION FROM THE PAPER.
        // See the comment in `AffGPublicInputs`.
        // Original: `Y^e`. Modified `Y^{-e}`.
        //
        // enc_1(z_2, w_y) == B_y (+) Y (*) (-e)
        if Ciphertext::new_public_with_randomizer(public.pk1, &self.z2, &self.w_y)
            != public.cap_y * &(-e) + self.cap_b_y.to_precomputed(public.pk1)
        {
            return false;
        }

        // s^{z_1} t^{z_3} == E S^e \mod \hat{N}
        let cap_e = self.cap_e.to_precomputed(setup);
        let cap_s = self.cap_s.to_precomputed(setup);
        if setup.commit(&self.z1, &self.z3) != &cap_e * &cap_s.pow(&e) {
            return false;
        }

        // s^{z_2} t^{z_4} == F T^e \mod \hat{N}
        let cap_f = self.cap_f.to_precomputed(setup);
        let cap_t = self.cap_t.to_precomputed(setup);
        if setup.commit(&self.z2, &self.z4) != &cap_f * &cap_t.pow(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use manul::{dev::BinaryFormat, session::WireFormat};
    use rand_core::OsRng;

    use super::{AffGProof, AffGPublicInputs, AffGSecretInputs};
    use crate::{
        dev::TestParams,
        paillier::{Ciphertext, RPParams, Randomizer, SecretKeyPaillierWire},
        params::{secret_scalar_from_signed, SchemeParams},
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

        let rp_params = RPParams::random(&mut OsRng);

        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(&mut OsRng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(&mut OsRng, Params::LP_BOUND);

        let rho = Randomizer::random(&mut OsRng, pk0);
        let rho_y = Randomizer::random(&mut OsRng, pk1);
        let secret = SecretSigned::random_in_exponent_range(&mut OsRng, Params::L_BOUND);
        let cap_c = Ciphertext::new(&mut OsRng, pk0, &secret);

        let cap_d = &cap_c * &x + Ciphertext::new_with_randomizer(pk0, &-&y, &rho);
        let cap_y = Ciphertext::new_with_randomizer(pk1, &y, &rho_y);
        let cap_x = secret_scalar_from_signed::<TestParams>(&x).mul_by_generator();

        let secret = AffGSecretInputs {
            x: &x,
            y: &y,
            rho: &rho,
            rho_y: &rho_y,
        };
        let public = AffGPublicInputs {
            pk0,
            pk1,
            cap_c: &cap_c,
            cap_d: &cap_d,
            cap_y: &cap_y,
            cap_x: &cap_x,
        };

        let proof = AffGProof::<Params>::new(&mut OsRng, secret, public, &rp_params, &aux);

        // Serialization roundtrip
        let serialized = BinaryFormat::serialize(proof).unwrap();
        let proof = BinaryFormat::deserialize::<AffGProof<Params>>(&serialized).unwrap();

        assert!(proof.verify(public, &rp_params, &aux));
    }
}
