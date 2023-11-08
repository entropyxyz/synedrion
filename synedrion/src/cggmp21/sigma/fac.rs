//! No small factor proof ($\Pi^{fac}$, Section C.5, Fig. 28)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{
    PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment, RPParamsMod,
    SecretKeyPaillierPrecomputed,
};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::{HasWide, Integer, NonZero, Signed};

const HASH_TAG: &[u8] = b"P_fac";

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct FacProof<P: SchemeParams> {
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
    pub fn random(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillierPrecomputed<P::Paillier>,
        aux_rp: &RPParamsMod<P::Paillier>, // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> Self {
        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e =
            Signed::from_xof_reader_bounded(&mut reader, &NonZero::new(P::CURVE_ORDER).unwrap());
        let e_wide = e.into_wide();

        let pk = sk.public_key();
        let hat_cap_n = &aux_rp.public_key().modulus_nonzero(); // $\hat{N}$

        // CHECK: using `2^(Paillier::PRIME_BITS - 1)` as $\sqrt{N_0}$ (which is its lower bound)
        let sqrt_cap_n = NonZero::new(
            <P::Paillier as PaillierParams>::Uint::ONE
                << (<P::Paillier as PaillierParams>::PRIME_BITS - 1),
        )
        .unwrap();

        let alpha = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n);
        let beta = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let nu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        // N_0 \hat{N}
        let scale = NonZero::new(pk.modulus().mul_wide(hat_cap_n.as_ref())).unwrap();

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

        let (p, q) = sk.primes();

        let cap_p = aux_rp.commit(&mu, &p).retrieve();
        let cap_q = aux_rp.commit(&nu, &q);
        let cap_a = aux_rp.commit_wide(&x, &alpha).retrieve();
        let cap_b = aux_rp.commit_wide(&y, &beta).retrieve();
        let cap_t = (&cap_q.pow_signed_wide(&alpha) * &aux_rp.commit_base_xwide(&r)).retrieve();

        let hat_sigma = sigma - (nu * p.into_wide()).into_wide();
        let z1 = alpha + (e * p).into_wide();
        let z2 = beta + (e * q).into_wide();
        let omega1 = x + e_wide * mu;
        let omega2 = y + e_wide * nu;
        let v = r + (e_wide.into_wide() * hat_sigma);

        Self {
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
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>,
        aux_rp: &RPParamsMod<P::Paillier>, // $s$, $t$
        aux: &impl Hashable,
    ) -> bool {
        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e =
            Signed::from_xof_reader_bounded(&mut reader, &NonZero::new(P::CURVE_ORDER).unwrap());

        let aux_pk = aux_rp.public_key();

        // R = s^{N_0} t^\sigma
        let cap_r = &aux_rp.commit_xwide(&self.sigma, &pk.modulus_bounded());

        // s^{z_1} t^{\omega_1} == A * P^e \mod \hat{N}
        let cap_a_mod = self.cap_a.to_mod(aux_pk);
        let cap_p_mod = self.cap_p.to_mod(aux_pk);
        if aux_rp.commit_wide(&self.omega1, &self.z1)
            != &cap_a_mod * &cap_p_mod.pow_signed_vartime(&e)
        {
            return false;
        }

        // s^{z_2} t^{\omega_2} == B * Q^e \mod \hat{N}
        let cap_b_mod = self.cap_b.to_mod(aux_pk);
        let cap_q_mod = self.cap_q.to_mod(aux_pk);
        if aux_rp.commit_wide(&self.omega2, &self.z2)
            != &cap_b_mod * &cap_q_mod.pow_signed_vartime(&e)
        {
            return false;
        }

        // Q^{z_1} * t^v == T * R^e \mod \hat{N}
        let cap_t_mod = self.cap_t.to_mod(aux_pk);
        if &cap_q_mod.pow_signed_wide(&self.z1) * &aux_rp.commit_base_xwide(&self.v)
            != &cap_t_mod * &cap_r.pow_signed_vartime(&e)
        {
            return false;
        }

        // z1 \in \pm \sqrt{N_0} 2^{\ell + \eps}
        if !self.z1.in_range_bits(
            P::L_BOUND + P::EPS_BOUND + <P::Paillier as PaillierParams>::PRIME_BITS - 1,
        ) {
            return false;
        }

        // z2 \in \pm \sqrt{N_0} 2^{\ell + \eps}
        if !self.z2.in_range_bits(
            P::L_BOUND + P::EPS_BOUND + <P::Paillier as PaillierParams>::PRIME_BITS - 1,
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
        let aux_rp = RPParamsMod::random(&mut OsRng, &aux_sk);

        let aux: &[u8] = b"abcde";

        let proof = FacProof::<Params>::random(&mut OsRng, &sk, &aux_rp, &aux);
        assert!(proof.verify(pk, &aux_rp, &aux));
    }
}
