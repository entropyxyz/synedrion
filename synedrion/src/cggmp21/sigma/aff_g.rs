//! Paillier Affine Operation with Group Commitment in Range ($\Pi^{aff-g}$, Section 6.2, Fig. 15)

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

const HASH_TAG: &[u8] = b"P_aff_g";

/**
ZK proof: Paillier Affine Operation with Group Commitment in Range.

NOTE: deviation from the paper here.
The proof in the paper assumes $D = C (*) x (+) enc_0(y, \rho)$.
But the way it is used in the Presigning, $D$ will actually be $... (+) enc_0(-y, \rho)$.
So we have to negate several variables when constructing the proof for the whole thing to work.

Secret inputs:
- $x \in \pm 2^\ell$,
- $y \in \pm 2^{\ell^\prime}$,
- $\rho$, a Paillier randomizer for the public key $N_0$,
- $\rho_y$, a Paillier randomizer for the public key $N_1$.

Public inputs:
- Paillier public keys $N_0$, $N_1$,
- Paillier ciphertext $C$ encrypted with $N_0$,
- Paillier ciphertext $D = C (*) x (+) enc_0(-y, \rho)$,
- Paillier ciphertext $Y = enc_1(y, \rho_y)$,
- Point $X = g * x$, where $g$ is the curve generator,
- Setup parameters ($\hat{N}$, $s$, $t$).
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AffGProof<P: SchemeParams> {
    e: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    cap_a: CiphertextWire<P::Paillier>,
    cap_b_x: Point,
    cap_b_y: CiphertextWire<P::Paillier>,
    cap_e: RPCommitmentWire<P::Paillier>,
    cap_s: RPCommitmentWire<P::Paillier>,
    cap_f: RPCommitmentWire<P::Paillier>,
    cap_t: RPCommitmentWire<P::Paillier>,
    z1: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    z2: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    z3: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    z4: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    omega: MaskedRandomizer<P::Paillier>,
    omega_y: MaskedRandomizer<P::Paillier>,
}

impl<P: SchemeParams> AffGProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        x: &SecretSigned<<P::Paillier as PaillierParams>::Uint>,
        y: &SecretSigned<<P::Paillier as PaillierParams>::Uint>,
        rho: &Randomizer<P::Paillier>,
        rho_y: &Randomizer<P::Paillier>,
        pk0: &PublicKeyPaillier<P::Paillier>,
        pk1: &PublicKeyPaillier<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,
        cap_d: &Ciphertext<P::Paillier>,
        cap_y: &Ciphertext<P::Paillier>,
        cap_x: &Point,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        x.assert_exponent_range(P::L_BOUND);
        y.assert_exponent_range(P::LP_BOUND);
        assert!(cap_c.public_key() == pk0);
        assert!(cap_d.public_key() == pk0);
        assert!(cap_y.public_key() == pk1);

        let hat_cap_n = setup.modulus();

        let alpha = SecretSigned::random_in_exp_range(rng, P::L_BOUND + P::EPS_BOUND);
        let beta = SecretSigned::random_in_exp_range(rng, P::LP_BOUND + P::EPS_BOUND);

        let r = Randomizer::random(rng, pk0);
        let r_y = Randomizer::random(rng, pk1);

        let gamma = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let m = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND, hat_cap_n);
        let delta = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let mu = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND, hat_cap_n);

        let cap_a = (cap_c * &alpha + Ciphertext::new_with_randomizer_signed(pk0, &beta, &r)).to_wire();
        let cap_b_x = secret_scalar_from_signed::<P>(&alpha).mul_by_generator();
        let cap_b_y = Ciphertext::new_with_randomizer_signed(pk1, &beta, &r_y).to_wire();
        let cap_e = setup.commit(&alpha, &gamma).to_wire();
        let cap_s = setup.commit(x, &m).to_wire();
        let cap_f = setup.commit(&beta, &delta).to_wire();

        // NOTE: deviation from the paper to support a different $D$
        // (see the comment in `AffGProof`)
        // Original: $s^y$. Modified: $s^{-y}$
        let cap_t = setup.commit(&(-y), &mu).to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_a)
            .chain(&cap_b_x)
            .chain(&cap_b_y)
            .chain(&cap_e)
            .chain(&cap_f)
            .chain(&cap_s)
            .chain(&cap_t)
            // public parameters
            .chain(pk0.as_wire())
            .chain(pk1.as_wire())
            .chain(&cap_c.to_wire())
            .chain(&cap_d.to_wire())
            .chain(&cap_y.to_wire())
            .chain(cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);
        let e_wide = e.to_wide();

        let z1 = (alpha + x * e).to_public();

        // NOTE: deviation from the paper to support a different $D$
        // (see the comment in `AffGProof`)
        // Original: $z_2 = \beta + e y$
        // Modified: $z_2 = \beta - e y$
        let z2 = (beta + (-y) * e).to_public();

        let z3 = (gamma + m * e_wide).to_public();
        let z4 = (delta + mu * e_wide).to_public();

        let omega = rho.to_masked(&r, &e);

        // NOTE: deviation from the paper to support a different $D$
        // (see the comment in `AffGProof`)
        // Original: $\rho_y^e$. Modified: $\rho_y^{-e}$.
        let omega_y = rho_y.to_masked(&r_y, &-e);

        Self {
            e,
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
            omega,
            omega_y,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        pk0: &PublicKeyPaillier<P::Paillier>,
        pk1: &PublicKeyPaillier<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,
        cap_d: &Ciphertext<P::Paillier>,
        cap_y: &Ciphertext<P::Paillier>,
        cap_x: &Point,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert!(cap_c.public_key() == pk0);
        assert!(cap_d.public_key() == pk0);
        assert!(cap_y.public_key() == pk1);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_a)
            .chain(&self.cap_b_x)
            .chain(&self.cap_b_y)
            .chain(&self.cap_e)
            .chain(&self.cap_f)
            .chain(&self.cap_s)
            .chain(&self.cap_t)
            // public parameters
            .chain(pk0.as_wire())
            .chain(pk1.as_wire())
            .chain(&cap_c.to_wire())
            .chain(&cap_d.to_wire())
            .chain(&cap_y.to_wire())
            .chain(cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // Range checks

        if !self.z1.in_range_bits(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        if !self.z2.in_range_bits(P::LP_BOUND + P::EPS_BOUND) {
            return false;
        }

        // C^{z_1} (1 + N_0)^{z_2} \omega^{N_0} = A D^e \mod N_0^2
        // => C (*) z_1 (+) encrypt_0(z_2, \omega) = A (+) D (*) e
        if cap_c * &self.z1 + Ciphertext::new_public_with_randomizer_signed(pk0, &self.z2, &self.omega)
            != cap_d * &e + self.cap_a.to_precomputed(pk0)
        {
            return false;
        }

        // g^{z_1} = B_x X^e
        if scalar_from_signed::<P>(&self.z1).mul_by_generator() != self.cap_b_x + cap_x * &scalar_from_signed::<P>(&e) {
            return false;
        }

        // NOTE: deviation from the paper to support a different `D`
        // (see the comment in `AffGProof`)
        // Original: `Y^e`. Modified `Y^{-e}`.
        // (1 + N_1)^{z_2} \omega_y^{N_1} = B_y Y^(-e) \mod N_1^2
        // => encrypt_1(z_2, \omega_y) = B_y (+) Y (*) (-e)
        if Ciphertext::new_public_with_randomizer_signed(pk1, &self.z2, &self.omega_y)
            != cap_y * &(-e) + self.cap_b_y.to_precomputed(pk1)
        {
            return false;
        }

        // s^{z_1} t^{z_3} = E S^e \mod \hat{N}
        let cap_e = self.cap_e.to_precomputed(setup);
        let cap_s = self.cap_s.to_precomputed(setup);
        if setup.commit(&self.z1, &self.z3) != &cap_e * &cap_s.pow(&e) {
            return false;
        }

        // s^{z_2} t^{z_4} = F T^e \mod \hat{N}
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
    use rand_core::OsRng;

    use super::AffGProof;
    use crate::{
        cggmp21::{conversion::secret_scalar_from_signed, SchemeParams, TestParams},
        paillier::{Ciphertext, RPParams, Randomizer, SecretKeyPaillierWire},
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

        let x = SecretSigned::random_in_exp_range(&mut OsRng, Params::L_BOUND);
        let y = SecretSigned::random_in_exp_range(&mut OsRng, Params::LP_BOUND);

        let rho = Randomizer::random(&mut OsRng, pk0);
        let rho_y = Randomizer::random(&mut OsRng, pk1);
        let secret = SecretSigned::random_in_exp_range(&mut OsRng, Params::L_BOUND);
        let cap_c = Ciphertext::new_signed(&mut OsRng, pk0, &secret);

        let cap_d = &cap_c * &x + Ciphertext::new_with_randomizer_signed(pk0, &-&y, &rho);
        let cap_y = Ciphertext::new_with_randomizer_signed(pk1, &y, &rho_y);
        let cap_x = secret_scalar_from_signed::<TestParams>(&x).mul_by_generator();

        let proof = AffGProof::<Params>::new(
            &mut OsRng, &x, &y, &rho, &rho_y, pk0, pk1, &cap_c, &cap_d, &cap_y, &cap_x, &rp_params, &aux,
        );
        assert!(proof.verify(pk0, pk1, &cap_c, &cap_d, &cap_y, &cap_x, &rp_params, &aux));
    }
}
