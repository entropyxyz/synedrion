//! Small-Factor Proof ($\Pi^{fac}$, Section A.4, Fig. 26)

use crypto_bigint::Integer;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    paillier::{PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams, SecretKeyPaillier},
    params::SchemeParams,
    tools::hashing::{Chain, Hashable, Hasher},
    uint::{MulWide, PublicSigned, SecretSigned},
};

const HASH_TAG: &[u8] = b"P_fac";

/**
ZK proof: No small factor proof.

Secret inputs:
- primes $p$, $q$ such that $p, q < ±\sqrt{N_0} 2^\ell$.

Public inputs:
- Paillier public key $N_0 = p * q$,
- Setup parameters ($\hat{N}$, $s$, $t$).
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FacProof<P: SchemeParams> {
    e: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    cap_p: RPCommitmentWire<P::Paillier>,
    cap_q: RPCommitmentWire<P::Paillier>,
    cap_a: RPCommitmentWire<P::Paillier>,
    cap_b: RPCommitmentWire<P::Paillier>,
    cap_t: RPCommitmentWire<P::Paillier>,
    z1: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    z2: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    w1: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    w2: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    v: PublicSigned<<P::Paillier as PaillierParams>::ExtraWideUint>,
}

impl<P: SchemeParams> FacProof<P> {
    pub fn new(
        rng: &mut dyn CryptoRngCore,
        sk0: &SecretKeyPaillier<P::Paillier>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        let pk0 = sk0.public_key();

        // TODO (#192): this assertion is currently not satisfied for TestParams.
        // assert!(pk0.modulus().bits_vartime() > 4 * P::L_BOUND);

        let hat_cap_n = setup.modulus(); // $\hat{N}$

        // NOTE: using `2^(Paillier::PRIME_BITS - 2)` as $\sqrt{N_0}$ (which is its lower bound)
        // According to the authors of the paper, it is acceptable.
        // In the end of the day, we're proving that `p, q < sqrt{N_0} 2^\ell`,
        // and really they should be `~ sqrt{N_0}`.
        // Note that it has to be matched when we check the range of
        // `z1` and `z2` during verification.
        let sqrt_cap_n =
            <P::Paillier as PaillierParams>::Uint::one() << (<P::Paillier as PaillierParams>::PRIME_BITS - 2);

        let alpha = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n);
        let beta = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, &sqrt_cap_n);
        let mu = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND, hat_cap_n);
        let nu = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND, hat_cap_n);

        // N_0 \hat{N}
        let scale = pk0.modulus().mul_wide(hat_cap_n);

        let r = SecretSigned::<<P::Paillier as PaillierParams>::Uint>::random_in_exponent_range_scaled_wide(
            rng,
            P::L_BOUND + P::EPS_BOUND,
            &scale,
        );
        let x = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let y = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let p = sk0.p_signed();
        let q = sk0.q_signed();

        let cap_p = setup.commit(&p, &mu).to_wire();
        let cap_q = setup.commit(&q, &nu);
        let cap_a = setup.commit(&alpha, &x).to_wire();
        let cap_b = setup.commit(&beta, &y).to_wire();
        let cap_t = (&cap_q.pow(&alpha) * &setup.commit_zero_value(&r)).to_wire();
        let cap_q = cap_q.to_wire();

        let mut reader = Hasher::<P::Digest>::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_p)
            .chain(&cap_q)
            .chain(&cap_a)
            .chain(&cap_b)
            .chain(&cap_t)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_in_exponent_range(&mut reader, P::L_BOUND);
        let e_wide = e.to_wide();

        let z1 = (alpha + (&p * e).to_wide()).to_public();
        let z2 = (beta + (q * e).to_wide()).to_public();
        let w1 = (x + mu * e_wide).to_public();
        let w2 = (y + &nu * e_wide).to_public();

        // p ∈ ±2^(MODULUS_BITS / 2)
        // e ∈ ±2^L_BOUND
        // nu ∈ ±2^(L_BOUND + MODULUS_BITS)
        // Now if scheme parameters are self-consistent,
        //    MODULUS_BITS >= LP_BOUND + EPS_BOUND
        //                 >= 3 * L_BOUND + 2 * EPS_BOUND
        //                 >= 5 * L_BOUND + 2 * SECURITY_PARAMETER
        // Therefore, `p * e * nu` will not overflow 2^(2*MODULUS_BITS) and will fit in `WideUint`.
        let v = (r - (p.mul_wide_public(&e) * nu).to_wide()).to_public();

        Self {
            e,
            cap_p,
            cap_q,
            cap_a,
            cap_b,
            cap_t,
            z1,
            z2,
            w1,
            w2,
            v,
        }
    }

    pub fn verify(
        &self,
        pk0: &PublicKeyPaillier<P::Paillier>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        let mut reader = Hasher::<P::Digest>::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_p)
            .chain(&self.cap_q)
            .chain(&self.cap_a)
            .chain(&self.cap_b)
            .chain(&self.cap_t)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_in_exponent_range(&mut reader, P::L_BOUND);

        if e != self.e {
            return false;
        }

        // NOTE: since when creating this proof we generated `alpha` and `beta`
        // using the approximation `sqrt(N_0) ~ 2^(PRIME_BITS - 2)`,
        // this is the bound we are using here as well.

        // z1 ∈ ±\sqrt{N_0} 2^{\ell + \eps}
        if !self
            .z1
            .is_in_exponent_range(P::L_BOUND + P::EPS_BOUND + <P::Paillier as PaillierParams>::PRIME_BITS - 2)
        {
            return false;
        }

        // z2 ∈ ±\sqrt{N_0} 2^{\ell + \eps}
        if !self
            .z2
            .is_in_exponent_range(P::L_BOUND + P::EPS_BOUND + <P::Paillier as PaillierParams>::PRIME_BITS - 2)
        {
            return false;
        }

        // R = s^{N_0}
        let cap_r = &setup.commit_zero_randomizer(&pk0.modulus_signed());

        // s^{z_1} t^{w_1} == A P^e \mod \hat{N}
        let cap_a = self.cap_a.to_precomputed(setup);
        let cap_p = self.cap_p.to_precomputed(setup);
        if setup.commit(&self.z1, &self.w1) != &cap_a * &cap_p.pow(&e) {
            return false;
        }

        // s^{z_2} t^{w_2} == B Q^e \mod \hat{N}
        let cap_b = self.cap_b.to_precomputed(setup);
        let cap_q = self.cap_q.to_precomputed(setup);
        if setup.commit(&self.z2, &self.w2) != &cap_b * &cap_q.pow(&e) {
            return false;
        }

        // Q^{z_1} * t^v == T R^e \mod \hat{N}
        let cap_t = self.cap_t.to_precomputed(setup);
        if &cap_q.pow(&self.z1) * &setup.commit_zero_value(&self.v) != &cap_t * &cap_r.pow(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use manul::{dev::BinaryFormat, session::WireFormat};
    use rand_core::OsRng;

    use super::FacProof;
    use crate::{
        dev::TestParams,
        paillier::{RPParams, SecretKeyPaillierWire},
        params::SchemeParams,
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

        // Serialization roundtrip
        let serialized = BinaryFormat::serialize(proof).unwrap();
        let proof = BinaryFormat::deserialize::<FacProof<Params>>(&serialized).unwrap();

        assert!(proof.verify(pk, &setup, &aux));
    }
}
