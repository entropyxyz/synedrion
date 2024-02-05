//! Paillier Affine Operation with Group Commitment in Range ($\Pi^{aff-g}$, Section 6.2, Fig. 15)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::curve::Point;
use crate::paillier::{
    Ciphertext, CiphertextMod, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment,
    RPParamsMod, Randomizer, RandomizerMod,
};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::Signed;

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
    e: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_a: Ciphertext<P::Paillier>,
    cap_b_x: Point,
    cap_b_y: Ciphertext<P::Paillier>,
    cap_e: RPCommitment<P::Paillier>,
    cap_s: RPCommitment<P::Paillier>,
    cap_f: RPCommitment<P::Paillier>,
    cap_t: RPCommitment<P::Paillier>,
    z1: Signed<<P::Paillier as PaillierParams>::Uint>,
    z2: Signed<<P::Paillier as PaillierParams>::Uint>,
    z3: Signed<<P::Paillier as PaillierParams>::WideUint>,
    z4: Signed<<P::Paillier as PaillierParams>::WideUint>,
    omega: Randomizer<P::Paillier>,
    omega_y: Randomizer<P::Paillier>,
}

impl<P: SchemeParams> AffGProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        x: &Signed<<P::Paillier as PaillierParams>::Uint>,
        y: &Signed<<P::Paillier as PaillierParams>::Uint>,
        rho: &RandomizerMod<P::Paillier>,
        rho_y: &RandomizerMod<P::Paillier>,
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        pk1: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_c: &CiphertextMod<P::Paillier>,
        cap_d: &CiphertextMod<P::Paillier>,
        cap_y: &CiphertextMod<P::Paillier>,
        cap_x: &Point,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        x.assert_bound(P::L_BOUND);
        y.assert_bound(P::LP_BOUND);
        assert!(cap_c.public_key() == pk0);
        assert!(cap_d.public_key() == pk0);
        assert!(cap_y.public_key() == pk1);

        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(pk0)
            .chain(pk1)
            .chain(cap_c)
            .chain(cap_d)
            .chain(cap_y)
            .chain(cap_x)
            .chain(setup)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);
        let e_wide = e.into_wide();

        let hat_cap_n = &setup.public_key().modulus_bounded();

        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let beta = Signed::random_bounded_bits(rng, P::LP_BOUND + P::EPS_BOUND);

        let r_mod = RandomizerMod::random(rng, pk0);
        let r_y_mod = RandomizerMod::random(rng, pk1);

        let gamma = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let m = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let delta = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        let cap_a = cap_c * alpha
            + CiphertextMod::new_with_randomizer_signed(pk0, &beta, &r_mod.retrieve());
        let cap_b_x = P::scalar_from_signed(&alpha).mul_by_generator();
        let cap_b_y = CiphertextMod::new_with_randomizer_signed(pk1, &beta, &r_y_mod.retrieve());
        let cap_e = setup.commit(&alpha, &gamma).retrieve();
        let cap_s = setup.commit(x, &m).retrieve();
        let cap_f = setup.commit(&beta, &delta).retrieve();

        // NOTE: deviation from the paper to support a different $D$
        // (see the comment in `AffGProof`)
        // Original: $s^y$. Modified: $s^{-y}$
        let cap_t = setup.commit(&-y, &mu).retrieve();

        let z1 = alpha + e * x;

        // NOTE: deviation from the paper to support a different $D$
        // (see the comment in `AffGProof`)
        // Original: $z_2 = \beta + e y$
        // Modified: $z_2 = \beta - e y$
        let z2 = beta + e * (-y);

        let z3 = gamma + e_wide * m;
        let z4 = delta + e_wide * mu;

        let omega = (r_mod * rho.pow_signed_vartime(&e)).retrieve();

        // NOTE: deviation from the paper to support a different $D$
        // (see the comment in `AffGProof`)
        // Original: $\rho_y^e$. Modified: $\rho_y^{-e}$.
        let omega_y = (r_y_mod * rho_y.pow_signed_vartime(&-e)).retrieve();

        Self {
            e,
            cap_a: cap_a.retrieve(),
            cap_b_x,
            cap_b_y: cap_b_y.retrieve(),
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
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        pk1: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_c: &CiphertextMod<P::Paillier>,
        cap_d: &CiphertextMod<P::Paillier>,
        cap_y: &CiphertextMod<P::Paillier>,
        cap_x: &Point,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert!(cap_c.public_key() == pk0);
        assert!(cap_d.public_key() == pk0);
        assert!(cap_y.public_key() == pk1);

        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(pk0)
            .chain(pk1)
            .chain(cap_c)
            .chain(cap_d)
            .chain(cap_y)
            .chain(cap_x)
            .chain(setup)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        let aux_pk = setup.public_key();

        // Range checks

        if !self.z1.in_range_bits(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        if !self.z2.in_range_bits(P::LP_BOUND + P::EPS_BOUND) {
            return false;
        }

        // C^{z_1} (1 + N_0)^{z_2} \omega^{N_0} = A D^e \mod N_0^2
        // => C (*) z_1 (+) encrypt_0(z_2, \omega) = A (+) D (*) e
        if cap_c * self.z1 + CiphertextMod::new_with_randomizer_signed(pk0, &self.z2, &self.omega)
            != cap_d * e + self.cap_a.to_mod(pk0)
        {
            return false;
        }

        // g^{z_1} = B_x X^e
        if P::scalar_from_signed(&self.z1).mul_by_generator()
            != self.cap_b_x + cap_x * &P::scalar_from_signed(&e)
        {
            return false;
        }

        // NOTE: deviation from the paper to support a different `D`
        // (see the comment in `AffGProof`)
        // Original: `Y^e`. Modified `Y^{-e}`.
        // (1 + N_1)^{z_2} \omega_y^{N_1} = B_y Y^(-e) \mod N_1^2
        // => encrypt_1(z_2, \omega_y) = B_y (+) Y (*) (-e)
        if CiphertextMod::new_with_randomizer_signed(pk1, &self.z2, &self.omega_y)
            != cap_y * (-e) + self.cap_b_y.to_mod(pk1)
        {
            return false;
        }

        // s^{z_1} t^{z_3} = E S^e \mod \hat{N}
        let cap_e_mod = self.cap_e.to_mod(aux_pk);
        let cap_s_mod = self.cap_s.to_mod(aux_pk);
        if setup.commit(&self.z1, &self.z3) != &cap_e_mod * &cap_s_mod.pow_signed_vartime(&e) {
            return false;
        }

        // s^{z_2} t^{z_4} = F T^e \mod \hat{N}
        let cap_f_mod = self.cap_f.to_mod(aux_pk);
        let cap_t_mod = self.cap_t.to_mod(aux_pk);
        if setup.commit(&self.z2, &self.z4) != &cap_f_mod * &cap_t_mod.pow_signed_vartime(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::AffGProof;
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::paillier::{CiphertextMod, RPParamsMod, RandomizerMod, SecretKeyPaillier};
    use crate::uint::Signed;

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk0 = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk0 = sk0.public_key();

        let sk1 = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk1 = sk1.public_key();

        let aux_sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let setup = RPParamsMod::random(&mut OsRng, &aux_sk);

        let aux: &[u8] = b"abcde";

        let x = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let y = Signed::random_bounded_bits(&mut OsRng, Params::LP_BOUND);

        let rho = RandomizerMod::random(&mut OsRng, pk0);
        let rho_y = RandomizerMod::random(&mut OsRng, pk1);
        let secret = Signed::random(&mut OsRng);
        let cap_c = CiphertextMod::new_signed(&mut OsRng, pk0, &secret);

        let cap_d =
            &cap_c * x + CiphertextMod::new_with_randomizer_signed(pk0, &-y, &rho.retrieve());
        let cap_y = CiphertextMod::new_with_randomizer_signed(pk1, &y, &rho_y.retrieve());
        let cap_x = Params::scalar_from_signed(&x).mul_by_generator();

        let proof = AffGProof::<Params>::new(
            &mut OsRng, &x, &y, &rho, &rho_y, pk0, pk1, &cap_c, &cap_d, &cap_y, &cap_x, &setup,
            &aux,
        );
        assert!(proof.verify(pk0, pk1, &cap_c, &cap_d, &cap_y, &cap_x, &setup, &aux));
    }
}
