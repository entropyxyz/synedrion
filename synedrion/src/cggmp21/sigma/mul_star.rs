//! Multiplication Paillier vs Group ($\Pi^{mul}$, Section C.6, Fig. 31)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    params::{scalar_from_signed, secret_scalar_from_signed},
    SchemeParams,
};
use crate::{
    curve::Point,
    paillier::{
        Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams,
        Randomizer,
    },
    tools::hashing::{Chain, Hashable, XofHasher},
    tools::Secret,
    uint::Signed,
};

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
    cap_a: CiphertextWire<P::Paillier>,
    cap_b_x: Point,
    cap_e: RPCommitmentWire<P::Paillier>,
    cap_s: RPCommitmentWire<P::Paillier>,
    z1: Signed<<P::Paillier as PaillierParams>::Uint>,
    z2: Signed<<P::Paillier as PaillierParams>::WideUint>,
    omega: MaskedRandomizer<P::Paillier>,
}

impl<P: SchemeParams> MulStarProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        x: &Secret<Signed<<P::Paillier as PaillierParams>::Uint>>,
        rho: &Randomizer<P::Paillier>,
        pk0: &PublicKeyPaillier<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,
        cap_d: &Ciphertext<P::Paillier>,
        cap_x: &Point,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        /*
        NOTE: Several issues with the proof description in the paper:
        - the prover creates $B_x$, but sends $B$ - a typo, and they're the same thing
        - the prover creates $r_y$, but it is unused - a typo
        - $\beta$ used to create $A$ is not mentioned anywhere else - a typo, it is effectively == 0
        */

        x.expose_secret().assert_bound(P::L_BOUND);
        assert_eq!(cap_c.public_key(), pk0);
        assert_eq!(cap_d.public_key(), pk0);

        let hat_cap_n = &setup.modulus_bounded(); // $\hat{N}$

        let r = Randomizer::random(rng, pk0);
        let alpha = Secret::init_with(|| Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND));
        let gamma = Secret::init_with(|| Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n));
        let m = Secret::init_with(|| Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n));

        let cap_a = (cap_c * &alpha).mul_randomizer(&r).to_wire();
        let cap_b_x = secret_scalar_from_signed::<P>(&alpha).mul_by_generator();
        let cap_e = setup.commit(&alpha, &gamma).to_wire();
        let cap_s = setup.commit(x, &m).to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_a)
            .chain(&cap_b_x)
            .chain(&cap_e)
            .chain(&cap_s)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&cap_c.to_wire())
            .chain(&cap_d.to_wire())
            .chain(cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = *(alpha + x * e).expose_secret();
        let z2 = *(gamma + m * e.to_wide()).expose_secret();
        let omega = rho.to_masked(&r, &e);

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
        pk0: &PublicKeyPaillier<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,
        cap_d: &Ciphertext<P::Paillier>,
        cap_x: &Point,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(cap_c.public_key(), pk0);
        assert_eq!(cap_d.public_key(), pk0);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_a)
            .chain(&self.cap_b_x)
            .chain(&self.cap_e)
            .chain(&self.cap_s)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&cap_c.to_wire())
            .chain(&cap_d.to_wire())
            .chain(cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // Range check
        if !self.z1.in_range_bits(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        // C (*) z_1 * \omega^{N_0} == A (+) D (*) e
        if (cap_c * self.z1).mul_masked_randomizer(&self.omega) != self.cap_a.to_precomputed(pk0) + cap_d * e {
            return false;
        }

        // g^{z_1} == B_x X^e
        if scalar_from_signed::<P>(&self.z1).mul_by_generator() != self.cap_b_x + cap_x * &scalar_from_signed::<P>(&e) {
            return false;
        }

        // s^{z_1} t^{z_2} == E S^e
        let cap_e = self.cap_e.to_precomputed(setup);
        let cap_s = self.cap_s.to_precomputed(setup);
        if setup.commit_public(&self.z1, &self.z2) != &cap_e * &cap_s.pow_signed_vartime(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::MulStarProof;
    use crate::{
        cggmp21::{params::secret_scalar_from_signed, SchemeParams, TestParams},
        paillier::{Ciphertext, RPParams, Randomizer, SecretKeyPaillierWire},
        tools::Secret,
        uint::Signed,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let setup = RPParams::random(&mut OsRng);

        let aux: &[u8] = b"abcde";

        let x = Secret::init_with(|| Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND));
        let secret = Secret::init_with(|| Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND));
        let rho = Randomizer::random(&mut OsRng, pk);
        let cap_c = Ciphertext::new_signed(&mut OsRng, pk, &secret);
        let cap_d = (&cap_c * &x).mul_randomizer(&rho);
        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        let proof = MulStarProof::<Params>::new(&mut OsRng, &x, &rho, pk, &cap_c, &cap_d, &cap_x, &setup, &aux);
        assert!(proof.verify(pk, &cap_c, &cap_d, &cap_x, &setup, &aux));
    }
}
