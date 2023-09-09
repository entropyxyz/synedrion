use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{
    PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment, RPParamsMod,
    SecretKeyPaillierPrecomputed,
};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::uint::{HasWide, Integer, NonZero, Signed};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct FacProof<P: SchemeParams> {
    cap_p: RPCommitment<P::Paillier>,
    cap_q: RPCommitment<P::Paillier>,
    cap_a: RPCommitment<P::Paillier>,
    cap_b: RPCommitment<P::Paillier>,
    cap_t: RPCommitment<P::Paillier>,
    sigma: Signed<<P::Paillier as PaillierParams>::OctoUint>,
    z1: Signed<<P::Paillier as PaillierParams>::QuadUint>,
    z2: Signed<<P::Paillier as PaillierParams>::QuadUint>,
    omega1: Signed<<P::Paillier as PaillierParams>::QuadUint>,
    omega2: Signed<<P::Paillier as PaillierParams>::QuadUint>,
    v: Signed<<P::Paillier as PaillierParams>::OctoUint>,
}

impl<P: SchemeParams> FacProof<P> {
    pub fn random(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillierPrecomputed<P::Paillier>,
        aux_rp: &RPParamsMod<P::Paillier>, // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> Self {
        let mut aux_rng = Hash::new_with_dst(b"P_log*").chain(aux).finalize_to_rng();

        let pk = sk.public_key();
        let hat_cap_n = &aux_rp.public_key().modulus_nonzero(); // $\hat{N}$

        // CHECK: using `2^(Paillier::PRIME_BITS - 1)` as $\sqrt{N_0}$ (which is its lower bound)
        let sqrt_cap_n = NonZero::new(
            <P::Paillier as PaillierParams>::DoubleUint::ONE
                << (<P::Paillier as PaillierParams>::PRIME_BITS - 1),
        )
        .unwrap();

        // \alpha <-- +- 2^{\ell + \eps} * \sqrt{N_0}
        let alpha = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n);

        // \beta <-- +- 2^{\ell + \eps} * \sqrt{N_0}
        let beta = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n);

        // \mu <-- (+- 2^\ell) \hat{N}
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        // \nu <-- (+- 2^\ell) \hat{N}
        let nu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        // N_0 \hat{N}
        let scale = NonZero::new(pk.modulus().mul_wide(hat_cap_n.as_ref())).unwrap();

        // \sigma <-- (+- 2^\ell) N_0 \hat{N}
        let sigma =
            Signed::<<P::Paillier as PaillierParams>::DoubleUint>::random_bounded_bits_scaled_wide(
                rng,
                P::L_BOUND,
                &scale,
            );

        // r <-- (+- 2^{\ell + \eps}) N_0 \hat{N}
        let r =
            Signed::<<P::Paillier as PaillierParams>::DoubleUint>::random_bounded_bits_scaled_wide(
                rng,
                P::L_BOUND + P::EPS_BOUND,
                &scale,
            );

        // x <-- (+- 2^{\ell + \eps}) \hat{N}
        let x = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        // y <-- (+- 2^{\ell + \eps}) \hat{N}
        let y = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let (p, q) = sk.primes();
        // TODO: return them as Signed already?
        let p_signed =
            Signed::new_positive(p, <P::Paillier as PaillierParams>::PRIME_BITS).unwrap();
        let q_signed =
            Signed::new_positive(q, <P::Paillier as PaillierParams>::PRIME_BITS).unwrap();

        // P = s^p t^\mu \mod \hat{N}
        let cap_p = aux_rp.commit(&mu, &p_signed).retrieve();

        // Q = s^q t^\nu \mod \hat{N}
        let cap_q = aux_rp.commit(&nu, &q_signed);

        // A = s^\alpha t^x \mod \hat{N}
        let cap_a = aux_rp.commit_wide(&x, &alpha).retrieve();

        // B = s^\beta t^y \mod \hat{N}
        let cap_b = aux_rp.commit_wide(&y, &beta).retrieve();

        // T = Q^\alpha t^r \mod \hat{N}
        // Another way is to rewrite it as
        //   s^{\alpha * q} t^{\alpha \nu + r} \mod \hat{N}
        // This may or may not be faster.
        let cap_t = (&cap_q.pow_signed_wide(&alpha) * &aux_rp.commit_base_octo(&r)).retrieve();

        // Non-interactive challenge ($e$)
        let challenge =
            Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // \hat{\sigma} = \sigma - \nu p
        let hat_sigma = sigma - (nu * p_signed.into_wide()).into_wide();

        // z_1 = \alpha + e p
        let z1 = alpha + (challenge * p_signed).into_wide();

        // z_2 = \beta + e q
        let z2 = beta + (challenge * q_signed).into_wide();

        // \omega_1 = x + e \mu
        let omega1 = x + challenge.into_wide() * mu;

        // \omega_2 = y + e \nu
        let omega2 = y + challenge.into_wide() * nu;

        // v = r + e \hat{\sigma}
        let v = r + (challenge.into_wide().into_wide() * hat_sigma);

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
        let mut aux_rng = Hash::new_with_dst(b"P_log*").chain(aux).finalize_to_rng();

        let aux_pk = aux_rp.public_key();

        // Non-interactive challenge ($e$)
        let challenge =
            Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // R = s^{N_0} t^\sigma
        let cap_r = &aux_rp.commit_octo(&self.sigma, pk.modulus());

        // s^{z_1} t^{\omega_1} == A * P^e \mod \hat{N}
        if aux_rp.commit_wide(&self.omega1, &self.z1)
            != &self.cap_a.to_mod(aux_pk) * &self.cap_p.to_mod(aux_pk).pow_signed(&challenge)
        {
            return false;
        }

        let cap_q_mod = self.cap_q.to_mod(aux_pk);

        // s^{z_2} t^{\omega_2} == B * Q^e \mod \hat{N}
        if aux_rp.commit_wide(&self.omega2, &self.z2)
            != &self.cap_b.to_mod(aux_pk) * &cap_q_mod.pow_signed(&challenge)
        {
            return false;
        }

        // Q^{z_1} * t^v == T * R^e \mod \hat{N}
        if &cap_q_mod.pow_signed_wide(&self.z1) * &aux_rp.commit_base_octo(&self.v)
            != &self.cap_t.to_mod(aux_pk) * &cap_r.pow_signed(&challenge)
        {
            return false;
        }

        // z1 \in +- \sqrt{N_0} 2^{\ell + \eps}
        if !self.z1.in_range_bits(
            P::L_BOUND + P::EPS_BOUND + <P::Paillier as PaillierParams>::PRIME_BITS - 1,
        ) {
            return false;
        }

        // z2 \in +- \sqrt{N_0} 2^{\ell + \eps}
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
