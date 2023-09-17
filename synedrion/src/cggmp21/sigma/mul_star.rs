//! Multiplication Paillier vs Group ($\Pi^{mul}$, Section C.6, Fig. 31)
#![allow(dead_code)] // TODO: to be used on erros in Signing protocol

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::curve::Point;
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment, RPParamsMod,
};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::uint::{FromScalar, NonZero, Retrieve, Signed, UintModLike};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct MulStarProof<P: SchemeParams> {
    cap_a: Ciphertext<P::Paillier>,                        // $A$
    cap_b_x: Point,                                        // $B_x$
    cap_e: RPCommitment<P::Paillier>,                      // $E$
    cap_s: RPCommitment<P::Paillier>,                      // $S$
    z1: Signed<<P::Paillier as PaillierParams>::Uint>,     // $z_1$
    z2: Signed<<P::Paillier as PaillierParams>::WideUint>, // $z_2$
    omega: <P::Paillier as PaillierParams>::Uint,          // $\omega$
}

impl<P: SchemeParams> MulStarProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn random(
        rng: &mut impl CryptoRngCore,
        x: &Signed<<P::Paillier as PaillierParams>::Uint>, // $x \in +- 2^\ell$
        rho: &<P::Paillier as PaillierParams>::Uint,       // $\rho \in \mathbb{Z}_{N_0}$
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>,    // $N_0$
        cap_c: &Ciphertext<P::Paillier>,                   // $C$, a ciphertext encrypted with `pk`
        aux_rp: &RPParamsMod<P::Paillier>,                 // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> Self {
        /*
        CHECK: Several issues with the proof description in the paper:
        - the prover creates $B_x$, but sends $B$ - probably a typo, and they're the same thing
        - the prover creates $r_y$, but it is unused - probably a typo
        - $\beta$ used to create $A$ is not mentioned anywhere else
          (and judging by the condition the verifier checks, it should be == 0)
        */

        // TODO: check ranges of input values
        let mut aux_rng = Hash::new_with_dst(b"P_aff_g").chain(aux).finalize_to_rng();

        let hat_cap_n = &aux_rp.public_key().modulus_nonzero(); // $\hat{N}$

        let e = Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        let r = pk.random_invertible_group_elem(rng);
        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let gamma = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let m = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        let cap_a = cap_c
            .homomorphic_mul(pk, &alpha)
            .mul_randomizer(pk, &r.retrieve());
        let cap_b_x = &Point::GENERATOR * &alpha.to_scalar();
        let cap_e = aux_rp.commit(&gamma, &alpha).retrieve();
        let cap_s = aux_rp.commit(&m, x).retrieve();

        let rho_mod = <P::Paillier as PaillierParams>::UintMod::new(rho, pk.precomputed_modulus());

        let z1 = alpha + e * *x;
        let z2 = gamma + e.into_wide() * m;
        let omega = (r * rho_mod.pow_signed_vartime(&e)).retrieve();

        Self {
            cap_a,
            cap_b_x,
            cap_e,
            cap_s,
            z1,
            z2,
            omega,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>, // $C$, a ciphertext encrypted with `pk`
        cap_d: &Ciphertext<P::Paillier>, // $D = C (*) x * \rho^{N_0} \mod N_0^2$
        cap_x: &Point,                   // $X = g * x$, where `g` is the curve generator
        aux_rp: &RPParamsMod<P::Paillier>, // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> bool {
        let mut aux_rng = Hash::new_with_dst(b"P_aff_g").chain(aux).finalize_to_rng();

        let aux_pk = aux_rp.public_key();

        let e = Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // C (*) z_1 * \omega^{N_0} == A (+) D (*) e
        if cap_c
            .homomorphic_mul(pk, &self.z1)
            .mul_randomizer(pk, &self.omega)
            != self
                .cap_a
                .homomorphic_add(pk, &cap_d.homomorphic_mul(pk, &e))
        {
            return false;
        }

        // g^{z_1} == B_x X^e
        if &Point::GENERATOR * &self.z1.to_scalar() != self.cap_b_x + cap_x * &e.to_scalar() {
            return false;
        }

        // s^{z_1} t^{z_2} == E S^e
        if aux_rp.commit(&self.z2, &self.z1)
            != &self.cap_e.to_mod(aux_pk) * &self.cap_s.to_mod(aux_pk).pow_signed_vartime(&e)
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::MulStarProof;
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::curve::Point;
    use crate::paillier::{Ciphertext, RPParamsMod, SecretKeyPaillier};
    use crate::uint::{FromScalar, Signed};

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let aux_sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let aux_rp = RPParamsMod::random(&mut OsRng, &aux_sk);

        let aux: &[u8] = b"abcde";

        let x = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        // TODO: use full range (0 to N)
        let secret = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let rho = Ciphertext::<Paillier>::randomizer(&mut OsRng, pk);
        let cap_c = Ciphertext::new_signed(&mut OsRng, pk, &secret);
        let cap_d = cap_c.homomorphic_mul(pk, &x).mul_randomizer(pk, &rho);
        let cap_x = &Point::GENERATOR * &x.to_scalar();

        let proof = MulStarProof::<Params>::random(&mut OsRng, &x, &rho, pk, &cap_c, &aux_rp, &aux);
        assert!(proof.verify(pk, &cap_c, &cap_d, &cap_x, &aux_rp, &aux));
    }
}
