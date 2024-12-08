//! No small factor proof ($\Pi^{fac}$, Section C.5, Fig. 28)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::{
    paillier::{PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams, SecretKeyPaillier},
    tools::{
        hashing::{Chain, Hashable, XofHasher},
        Secret,
    },
    uint::{Bounded, Integer, Signed},
};

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
    cap_p: RPCommitmentWire<P::Paillier>,
    cap_q: RPCommitmentWire<P::Paillier>,
    cap_a: RPCommitmentWire<P::Paillier>,
    cap_b: RPCommitmentWire<P::Paillier>,
    cap_t: RPCommitmentWire<P::Paillier>,
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
        sk0: &SecretKeyPaillier<P::Paillier>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        let pk0 = sk0.public_key();

        let hat_cap_n = &setup.modulus_bounded(); // $\hat{N}$

        // NOTE: using `2^(Paillier::PRIME_BITS - 2)` as $\sqrt{N_0}$ (which is its lower bound)
        // According to the authors of the paper, it is acceptable.
        // In the end of the day, we're proving that `p, q < sqrt{N_0} 2^\ell`,
        // and really they should be `~ sqrt{N_0}`.
        // Note that it has to be matched when we check the range of
        // `z1` and `z2` during verification.
        let sqrt_cap_n = Bounded::new(
            <P::Paillier as PaillierParams>::Uint::one() << (<P::Paillier as PaillierParams>::PRIME_BITS - 2),
            <P::Paillier as PaillierParams>::PRIME_BITS,
        )
        .expect("the value is bounded by `2^PRIME_BITS` by construction");

        let alpha =
            Secret::init_with(|| Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n));
        let beta =
            Secret::init_with(|| Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n));
        let mu = Secret::init_with(|| Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n));
        let nu = Secret::init_with(|| Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n));

        // N_0 \hat{N}
        let scale = pk0.modulus_bounded().mul_wide(hat_cap_n);

        let sigma =
            Signed::<<P::Paillier as PaillierParams>::Uint>::random_bounded_bits_scaled_wide(rng, P::L_BOUND, &scale);
        let r = Secret::init_with(|| {
            Signed::<<P::Paillier as PaillierParams>::Uint>::random_bounded_bits_scaled_wide(
                rng,
                P::L_BOUND + P::EPS_BOUND,
                &scale,
            )
        });
        let x = Secret::init_with(|| Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n));
        let y = Secret::init_with(|| Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n));

        let p = sk0.p_signed();
        let q = sk0.q_signed();

        let cap_p = setup.commit(&p, &mu).to_wire();
        let cap_q = setup.commit(&q, &nu);
        let cap_a = setup.commit_wide(&alpha, &x).to_wire();
        let cap_b = setup.commit_wide(&beta, &y).to_wire();
        let cap_t = (&cap_q.pow_signed_wide(&alpha) * &setup.commit_zero_xwide(&r)).to_wire();
        let cap_q = cap_q.to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_p)
            .chain(&cap_q)
            .chain(&cap_a)
            .chain(&cap_b)
            .chain(&cap_t)
            .chain(&sigma)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);
        let e_wide = e.to_wide();

        let p_wide = sk0.p_wide_signed();

        let hat_sigma = sigma - (p_wide * &nu).expose_secret().to_wide();
        let z1 = *(alpha + (p * e).to_wide()).expose_secret();
        let z2 = *(beta + (q * e).to_wide()).expose_secret();
        let omega1 = *(x + mu * e_wide).expose_secret();
        let omega2 = *(nu * e_wide + &y).expose_secret();
        let v = *(r + &(hat_sigma * e_wide.to_wide())).expose_secret();

        Self {
            e,
            cap_p,
            cap_q,
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
        pk0: &PublicKeyPaillier<P::Paillier>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_p)
            .chain(&self.cap_q)
            .chain(&self.cap_a)
            .chain(&self.cap_b)
            .chain(&self.cap_t)
            .chain(&self.sigma)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // R = s^{N_0} t^\sigma
        let cap_r = &setup.commit_public_xwide(&pk0.modulus_bounded(), &self.sigma);

        // s^{z_1} t^{\omega_1} == A * P^e \mod \hat{N}
        let cap_a = self.cap_a.to_precomputed(setup);
        let cap_p = self.cap_p.to_precomputed(setup);
        if setup.commit_public_wide(&self.z1, &self.omega1) != &cap_a * &cap_p.pow_signed_vartime(&e) {
            return false;
        }

        // s^{z_2} t^{\omega_2} == B * Q^e \mod \hat{N}
        let cap_b = self.cap_b.to_precomputed(setup);
        let cap_q = self.cap_q.to_precomputed(setup);
        if setup.commit_public_wide(&self.z2, &self.omega2) != &cap_b * &cap_q.pow_signed_vartime(&e) {
            return false;
        }

        // Q^{z_1} * t^v == T * R^e \mod \hat{N}
        let cap_t = self.cap_t.to_precomputed(setup);
        if &cap_q.pow_signed_wide_vartime(&self.z1) * &setup.commit_public_base_xwide(&self.v)
            != &cap_t * &cap_r.pow_signed_vartime(&e)
        {
            return false;
        }

        // NOTE: since when creating this proof we generated `alpha` and `beta`
        // using the approximation `sqrt(N_0) ~ 2^(PRIME_BITS - 2)`,
        // this is the bound we are using here as well.

        // z1 \in \pm \sqrt{N_0} 2^{\ell + \eps}
        if !self
            .z1
            .in_range_bits(P::L_BOUND + P::EPS_BOUND + <P::Paillier as PaillierParams>::PRIME_BITS - 2)
        {
            return false;
        }

        // z2 \in \pm \sqrt{N_0} 2^{\ell + \eps}
        if !self
            .z2
            .in_range_bits(P::L_BOUND + P::EPS_BOUND + <P::Paillier as PaillierParams>::PRIME_BITS - 2)
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::FacProof;
    use crate::{
        cggmp21::{SchemeParams, TestParams},
        paillier::{RPParams, SecretKeyPaillierWire},
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let setup = RPParams::random(&mut OsRng);

        let aux: &[u8] = b"abcde";

        let proof = FacProof::<Params>::new(&mut OsRng, &sk, &setup, &aux);
        assert!(proof.verify(pk, &setup, &aux));
    }
}
