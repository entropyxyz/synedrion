//! Multiplication Paillier vs Group ($\Pi^{mul}$, Section C.6, Fig. 31)

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

const HASH_TAG: &[u8] = b"P_mul*";

/**
ZK proof: Multiplication Paillier vs Group.

Secret inputs:
- $x \in +- 2^\ell$,
- $\rho$, a Paillier randomizer for the public key $N_0$.

Public inputs:
- Paillier public key $N_0$,
- Paillier ciphertext $C$ encrypted with $N_0$,
- Paillier ciphertext $D = (C (*) x) * \rho^{N_0} \mod N_0^2$,
- Point $X = g * x$, where $g$ is the curve generator,
- Setup parameters ($\hat{N}$, $s$, $t$).
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MulStarProof<P: SchemeParams> {
    e: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_a: Ciphertext<P::Paillier>,
    cap_b_x: Point,
    cap_e: RPCommitment<P::Paillier>,
    cap_s: RPCommitment<P::Paillier>,
    z1: Signed<<P::Paillier as PaillierParams>::Uint>,
    z2: Signed<<P::Paillier as PaillierParams>::WideUint>,
    omega: Randomizer<P::Paillier>,
}

impl<P: SchemeParams> MulStarProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        x: &Signed<<P::Paillier as PaillierParams>::Uint>,
        rho: &RandomizerMod<P::Paillier>,
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_c: &CiphertextMod<P::Paillier>,
        cap_d: &CiphertextMod<P::Paillier>,
        cap_x: &Point,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        /*
        NOTE: Several issues with the proof description in the paper:
        - the prover creates $B_x$, but sends $B$ - a typo, and they're the same thing
        - the prover creates $r_y$, but it is unused - a typo
        - $\beta$ used to create $A$ is not mentioned anywhere else - a typo, it is effectively == 0
        */

        x.assert_bound(P::L_BOUND);
        assert_eq!(cap_c.public_key(), pk0);
        assert_eq!(cap_d.public_key(), pk0);

        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(pk0)
            .chain(cap_c)
            .chain(cap_d)
            .chain(cap_x)
            .chain(setup)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let hat_cap_n = &setup.public_key().modulus_bounded(); // $\hat{N}$

        let r = RandomizerMod::random(rng, pk0);
        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let gamma = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let m = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        let cap_a = cap_c.homomorphic_mul(&alpha).mul_randomizer(&r.retrieve());
        let cap_b_x = P::scalar_from_signed(&alpha).mul_by_generator();
        let cap_e = setup.commit(&alpha, &gamma).retrieve();
        let cap_s = setup.commit(x, &m).retrieve();

        let z1 = alpha + e * x;
        let z2 = gamma + e.into_wide() * m;
        let omega = (r * rho.pow_signed(&e)).retrieve();

        Self {
            e,
            cap_a: cap_a.retrieve(),
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
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_c: &CiphertextMod<P::Paillier>,
        cap_d: &CiphertextMod<P::Paillier>,
        cap_x: &Point,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(cap_c.public_key(), pk0);
        assert_eq!(cap_d.public_key(), pk0);

        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(pk0)
            .chain(cap_c)
            .chain(cap_d)
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

        // C (*) z_1 * \omega^{N_0} == A (+) D (*) e
        if cap_c.homomorphic_mul(&self.z1).mul_randomizer(&self.omega)
            != self
                .cap_a
                .to_mod(pk0)
                .homomorphic_add(&cap_d.homomorphic_mul(&e))
        {
            return false;
        }

        // g^{z_1} == B_x X^e
        if P::scalar_from_signed(&self.z1).mul_by_generator()
            != self.cap_b_x + cap_x * &P::scalar_from_signed(&e)
        {
            return false;
        }

        // s^{z_1} t^{z_2} == E S^e
        let cap_e_mod = self.cap_e.to_mod(aux_pk);
        let cap_s_mod = self.cap_s.to_mod(aux_pk);
        if setup.commit(&self.z1, &self.z2) != &cap_e_mod * &cap_s_mod.pow_signed_vartime(&e) {
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
    use crate::paillier::{CiphertextMod, RPParamsMod, RandomizerMod, SecretKeyPaillier};
    use crate::uint::Signed;

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let aux_sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let setup = RPParamsMod::random(&mut OsRng, &aux_sk);

        let aux: &[u8] = b"abcde";

        let x = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let secret = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let rho = RandomizerMod::random(&mut OsRng, pk);
        let cap_c = CiphertextMod::new_signed(&mut OsRng, pk, &secret);
        let cap_d = cap_c.homomorphic_mul(&x).mul_randomizer(&rho.retrieve());
        let cap_x = Params::scalar_from_signed(&x).mul_by_generator();

        let proof = MulStarProof::<Params>::new(
            &mut OsRng, &x, &rho, pk, &cap_c, &cap_d, &cap_x, &setup, &aux,
        );
        assert!(proof.verify(pk, &cap_c, &cap_d, &cap_x, &setup, &aux));
    }
}
