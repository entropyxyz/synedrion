//! No small factor proof ($\Pi^{fac}$, Section C.5, Fig. 28)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{
    PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment, RPParamsMod,
    SecretKeyPaillierPrecomputed,
};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::{Bounded, Integer, Signed};

const HASH_TAG: &[u8] = b"P_fac";

/**
ZK proof: No small factor proof.

Secret inputs:
- primes $p$, $q$ such that $p, q < \pm \sqrt{N_0} 2^\ell$.

Public inputs:
- Paillier public key $N_0 = p * q$,
- Setup parameters ($\hat{N}$, $s$, $t$).
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FacProof<P: SchemeParams> {
    e: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_p: RPCommitment<P::Paillier>,
    cap_q: RPCommitment<P::Paillier>,
    cap_a: RPCommitment<P::Paillier>,
    cap_b: RPCommitment<P::Paillier>,
    cap_t: RPCommitment<P::Paillier>,
    sigma: Signed<<P::Paillier as PaillierParams>::ExtraWideUint>,
    z1: Signed<<P::Paillier as PaillierParams>::WideUint>,
    z2: Signed<<P::Paillier as PaillierParams>::WideUint>,
    omega1: Signed<<P::Paillier as PaillierParams>::WideUint>,
    omega2: Signed<<P::Paillier as PaillierParams>::WideUint>,
    v: Signed<<P::Paillier as PaillierParams>::ExtraWideUint>,
}

impl<P: SchemeParams> FacProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        sk0: &SecretKeyPaillierPrecomputed<P::Paillier>,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        let pk0 = sk0.public_key();

        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(pk0)
            .chain(setup)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);
        let e_wide = e.into_wide();

        let hat_cap_n = &setup.public_key().modulus_bounded(); // $\hat{N}$

        // NOTE: using `2^(Paillier::PRIME_BITS - 2)` as $\sqrt{N_0}$ (which is its lower bound)
        // According to the authors of the paper, it is acceptable.
        // In the end of the day, we're proving that `p, q < sqrt{N_0} 2^\ell`,
        // and really they should be `~ sqrt{N_0}`.
        // Note that it has to be matched when we check the range of
        // `z1` and `z2` during verification.
        let sqrt_cap_n = Bounded::new(
            <P::Paillier as PaillierParams>::Uint::ONE
                << (<P::Paillier as PaillierParams>::PRIME_BITS - 2),
            <P::Paillier as PaillierParams>::PRIME_BITS as u32,
        )
        .unwrap();

        let alpha = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n);
        let beta = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let nu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        // N_0 \hat{N}
        let scale = pk0.modulus_bounded().mul_wide(hat_cap_n);

        let sigma =
            Signed::<<P::Paillier as PaillierParams>::Uint>::random_bounded_bits_scaled_wide(
                rng,
                P::L_BOUND,
                &scale,
            );
        let r = Signed::<<P::Paillier as PaillierParams>::Uint>::random_bounded_bits_scaled_wide(
            rng,
            P::L_BOUND + P::EPS_BOUND,
            &scale,
        );
        let x = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let y = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let (p, q) = sk0.primes();

        let cap_p = setup.commit(&p, &mu).retrieve();
        let cap_q = setup.commit(&q, &nu);
        let cap_a = setup.commit_wide(&alpha, &x).retrieve();
        let cap_b = setup.commit_wide(&beta, &y).retrieve();
        let cap_t = (&cap_q.pow_signed_wide(&alpha) * &setup.commit_base_xwide(&r)).retrieve();

        let hat_sigma = sigma - (nu * p.into_wide()).into_wide();
        let z1 = alpha + (e * p).into_wide();
        let z2 = beta + (e * q).into_wide();
        let omega1 = x + e_wide * mu;
        let omega2 = y + e_wide * nu;
        let v = r + (e_wide.into_wide() * hat_sigma);

        Self {
            e,
            cap_p,
            cap_q: cap_q.retrieve(),
            cap_a,
            cap_b,
            cap_t,
            sigma,
            z1,
            z2,
            omega1,
            omega2,
            v,
        }
    }

    pub fn verify(
        &self,
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(pk0)
            .chain(setup)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        let aux_pk = setup.public_key();

        // R = s^{N_0} t^\sigma
        let cap_r = &setup.commit_xwide(&pk0.modulus_bounded(), &self.sigma);

        // s^{z_1} t^{\omega_1} == A * P^e \mod \hat{N}
        let cap_a_mod = self.cap_a.to_mod(aux_pk);
        let cap_p_mod = self.cap_p.to_mod(aux_pk);
        if setup.commit_wide(&self.z1, &self.omega1)
            != &cap_a_mod * &cap_p_mod.pow_signed_vartime(&e)
        {
            return false;
        }

        // s^{z_2} t^{\omega_2} == B * Q^e \mod \hat{N}
        let cap_b_mod = self.cap_b.to_mod(aux_pk);
        let cap_q_mod = self.cap_q.to_mod(aux_pk);
        if setup.commit_wide(&self.z2, &self.omega2)
            != &cap_b_mod * &cap_q_mod.pow_signed_vartime(&e)
        {
            return false;
        }

        // Q^{z_1} * t^v == T * R^e \mod \hat{N}
        let cap_t_mod = self.cap_t.to_mod(aux_pk);
        if &cap_q_mod.pow_signed_wide(&self.z1) * &setup.commit_base_xwide(&self.v)
            != &cap_t_mod * &cap_r.pow_signed_vartime(&e)
        {
            return false;
        }

        // NOTE: since when creating this proof we generated `alpha` and `beta`
        // using the approximation `sqrt(N_0) ~ 2^(PRIME_BITS - 2)`,
        // this is the bound we are using here as well.

        // z1 \in \pm \sqrt{N_0} 2^{\ell + \eps}
        if !self.z1.in_range_bits(
            P::L_BOUND + P::EPS_BOUND + <P::Paillier as PaillierParams>::PRIME_BITS - 2,
        ) {
            return false;
        }

        // z2 \in \pm \sqrt{N_0} 2^{\ell + \eps}
        if !self.z2.in_range_bits(
            P::L_BOUND + P::EPS_BOUND + <P::Paillier as PaillierParams>::PRIME_BITS - 2,
        ) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::FacProof;
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::paillier::{RPParamsMod, SecretKeyPaillier};

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let aux_sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let setup = RPParamsMod::random(&mut OsRng, &aux_sk);

        let aux: &[u8] = b"abcde";

        let proof = FacProof::<Params>::new(&mut OsRng, &sk, &setup, &aux);
        assert!(proof.verify(pk, &setup, &aux));
    }
}
