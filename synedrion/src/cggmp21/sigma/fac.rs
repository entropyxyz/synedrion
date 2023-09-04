use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{
    PaillierParams, PublicKeyPaillier, RPCommitment, RPParamsMod, SecretKeyPaillier,
};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::uint::{CheckedAdd, HasWide, Integer, NonZero, RandomMod, Signed, UintLike};

pub fn mul_mod<P: PaillierParams>(
    x: &P::DoubleUint,
    y: &P::DoubleUint,
    modulus: &NonZero<P::DoubleUint>,
) -> P::DoubleUint {
    let prod_wide = x.mul_wide(y);
    // TODO: note that currently `rem()` isn't constant-time
    // (to be made constant-time in future releases of crypto-bigint).
    // Our modulus is phi(\hat{N}) which technically isn't secret.
    let rem_wide = prod_wide % NonZero::new(modulus.as_ref().into_wide()).unwrap();
    P::DoubleUint::try_from_wide(rem_wide).unwrap()
}

// CHECK: since bound_bits + bits(scale1) + bits(scale2) would overflow QuadUint,
// we temporarily generate the result modulo phi(\hat{N}).
// Is it safe to send over the wire? If not, we will have to use something
// even larger than QuadUint.
pub fn random_bounded_bits_double_scaled<P: PaillierParams>(
    rng: &mut impl CryptoRngCore,
    bound_bits: usize,
    scale1: &NonZero<P::DoubleUint>,
    scale2: &NonZero<P::DoubleUint>,
    modulus: &NonZero<P::DoubleUint>,
) -> P::DoubleUint {
    // TODO: check the ranges
    let bound = NonZero::new(P::DoubleUint::ONE << bound_bits).unwrap();
    let positive_bound = (*bound.as_ref() << 1)
        .checked_add(&P::DoubleUint::ONE)
        .unwrap();
    let positive_result = P::DoubleUint::random_mod(rng, &NonZero::new(positive_bound).unwrap());

    mul_mod::<P>(
        &mul_mod::<P>(&positive_result, scale1, modulus),
        scale2,
        modulus,
    )
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct FacProof<P: SchemeParams> {
    cap_p: RPCommitment<P::Paillier>,
    cap_q: RPCommitment<P::Paillier>,
    cap_a: RPCommitment<P::Paillier>,
    cap_b: RPCommitment<P::Paillier>,
    cap_t: RPCommitment<P::Paillier>,
    sigma: Signed<<P::Paillier as PaillierParams>::QuadUint>,
    z1: Signed<<P::Paillier as PaillierParams>::QuadUint>,
    z2: Signed<<P::Paillier as PaillierParams>::QuadUint>,
    omega1: Signed<<P::Paillier as PaillierParams>::QuadUint>,
    omega2: Signed<<P::Paillier as PaillierParams>::QuadUint>,
    v: <P::Paillier as PaillierParams>::DoubleUint,
}

impl<P: SchemeParams> FacProof<P> {
    pub fn random(
        rng: &mut impl CryptoRngCore,
        sk: &SecretKeyPaillier<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        let mut aux_rng = Hash::new_with_dst(b"P_log*").chain(aux).finalize_to_rng();
        let aux_sk = SecretKeyPaillier::<P::Paillier>::random(&mut aux_rng);
        let aux_pk = aux_sk.public_key(); // `\hat{N}`

        let rp = RPParamsMod::random(&mut aux_rng, &aux_sk);

        let pk = sk.public_key();
        let hat_phi = aux_sk.totient();

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
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, &aux_pk.modulus());

        // \nu <-- (+- 2^\ell) \hat{N}
        let nu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, &aux_pk.modulus());

        // \sigma <-- (+- 2^\ell) N_0 \hat{N}
        let sigma_mod = random_bounded_bits_double_scaled::<P::Paillier>(
            rng,
            P::L_BOUND,
            &pk.modulus(),
            &aux_pk.modulus(),
            &hat_phi,
        );
        let sigma = sigma_mod.into_wide();
        let sigma = Signed::new_positive(sigma).unwrap();

        // r <-- (+- 2^{\ell + \eps}) N_0 \hat{N}
        let r = random_bounded_bits_double_scaled::<P::Paillier>(
            rng,
            P::L_BOUND + P::EPS_BOUND,
            &pk.modulus(),
            &aux_pk.modulus(),
            &hat_phi,
        );

        // x <-- (+- 2^{\ell + \eps}) \hat{N}
        let x =
            Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &aux_pk.modulus());

        // y <-- (+- 2^{\ell + \eps}) \hat{N}
        let y =
            Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &aux_pk.modulus());

        let (p, q) = sk.primes();
        let p_signed = Signed::new_positive(p).unwrap();
        //let p_signed_wide = Signed::new_positive(p.into_wide()).unwrap();
        let q_signed = Signed::new_positive(q).unwrap();

        // P = s^p t^\mu \mod \hat{N}
        let cap_p = rp.commit(&mu, &p_signed).retrieve();

        // Q = s^q t^\nu \mod \hat{N}
        let cap_q = rp.commit(&nu, &q_signed);

        // A = s^\alpha t^x \mod \hat{N}
        let cap_a = rp.commit_wide(&x, &alpha).retrieve();

        // B = s^\beta t^y \mod \hat{N}
        let cap_b = rp.commit_wide(&y, &beta).retrieve();

        // T = Q^\alpha t^r \mod \hat{N}
        // Another way is to rewrite it as
        //   s^{\alpha * q} t^{\alpha \nu + r} \mod \hat{N}
        // This may or may not be faster.
        let cap_t = (&cap_q.pow_signed_wide(&alpha) * &rp.commit_base(&r)).retrieve();

        // Non-interactive challenge ($e$)
        let challenge =
            Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // \hat{\sigma} = \sigma - \nu p
        //let hat_sigma = sigma - nu * p_signed_wide;

        // z_1 = \alpha + e p
        let z1 = alpha + (challenge * p_signed).into_wide();

        // z_2 = \beta + e q
        let z2 = beta + (challenge * q_signed).into_wide();

        // \omega_1 = x + e \mu
        let omega1 = x + challenge.into_wide() * mu;

        // \omega_2 = y + e \nu
        let omega2 = y + challenge.into_wide() * nu;

        // v = r + e \hat{\sigma}
        // CHECK: calculating modulo \phi(\hat{N}) so that it fits into the variable
        // for the uint sizes in test parameters.
        let nu_times_p = mul_mod::<P::Paillier>(&nu.extract_mod_half(&hat_phi), &p, &hat_phi);
        let hat_sigma = sigma
            .extract_mod_half(&hat_phi)
            .sub_mod(&nu_times_p, &hat_phi);
        let v = r.add_mod(
            &mul_mod::<P::Paillier>(&hat_sigma, &challenge.extract_mod(&hat_phi), &hat_phi),
            &hat_phi,
        );

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

    pub fn verify(&self, pk: &PublicKeyPaillier<P::Paillier>, aux: &impl Hashable) -> bool {
        let mut aux_rng = Hash::new_with_dst(b"P_log*").chain(aux).finalize_to_rng();
        let aux_sk = SecretKeyPaillier::<P::Paillier>::random(&mut aux_rng);
        let aux_pk = aux_sk.public_key(); // `\hat{N}`

        let rp = RPParamsMod::random(&mut aux_rng, &aux_sk);

        // Non-interactive challenge ($e$)
        let challenge =
            Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // R = s^{N_0} t^\sigma
        let cap_r = &rp.commit_positive(&self.sigma, pk.modulus().as_ref());

        // s^{z_1} t^{\omega_1} == A * P^e \mod \hat{N}
        if rp.commit_wide(&self.omega1, &self.z1)
            != &self.cap_a.to_mod(&aux_pk) * &self.cap_p.to_mod(&aux_pk).pow_signed(&challenge)
        {
            return false;
        }

        let cap_q_mod = self.cap_q.to_mod(&aux_pk);

        // s^{z_2} t^{\omega_2} == B * Q^e \mod \hat{N}
        if rp.commit_wide(&self.omega2, &self.z2)
            != &self.cap_b.to_mod(&aux_pk) * &cap_q_mod.pow_signed(&challenge)
        {
            return false;
        }

        // Q^{z_1} * t^v == T * R^e \mod \hat{N}
        if &cap_q_mod.pow_signed_wide(&self.z1) * &rp.commit_base(&self.v)
            != &self.cap_t.to_mod(&aux_pk) * &cap_r.pow_signed(&challenge)
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
    use crate::paillier::SecretKeyPaillier;

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng);
        let pk = sk.public_key();

        let aux: &[u8] = b"abcde";

        let proof = FacProof::<Params>::random(&mut OsRng, &sk, &aux);
        assert!(proof.verify(&pk, &aux));
    }
}
