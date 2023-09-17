//! Paillier decryption modulo $q$ ($\Pi^{dec}$, Section C.6, Fig. 30)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::curve::Scalar;
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment, RPParamsMod,
};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::uint::{Bounded, FromScalar, NonZero, Retrieve, Signed, UintModLike};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct DecProof<P: SchemeParams> {
    cap_s: RPCommitment<P::Paillier>,
    cap_t: RPCommitment<P::Paillier>,
    cap_a: Ciphertext<P::Paillier>,
    gamma: Scalar,
    z1: Signed<<P::Paillier as PaillierParams>::Uint>,
    z2: Signed<<P::Paillier as PaillierParams>::WideUint>,
    omega: <P::Paillier as PaillierParams>::Uint,
}

impl<P: SchemeParams> DecProof<P> {
    pub fn random(
        rng: &mut impl CryptoRngCore,
        y: &Bounded<<P::Paillier as PaillierParams>::Uint>,
        rho: &<P::Paillier as PaillierParams>::Uint,
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>, // $N$
        aux_rp: &RPParamsMod<P::Paillier>,              // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> Self {
        let mut aux_rng = Hash::new_with_dst(b"P_enc").chain(aux).finalize_to_rng();
        let e = Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        let hat_cap_n = &aux_rp.public_key().modulus_nonzero(); // $\hat{N}$

        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let nu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let r = pk.random_invertible_group_elem(rng);

        let cap_s = aux_rp.commit_bounded(&mu, y).retrieve();
        let cap_t = aux_rp.commit(&nu, &alpha).retrieve();
        let cap_a = Ciphertext::new_with_randomizer_signed(pk, &alpha, &r.retrieve());
        let gamma = alpha.to_scalar();

        let z1 = alpha + e * y.into_signed().unwrap();
        let z2 = nu + e.into_wide() * mu;

        let rho_mod = <P::Paillier as PaillierParams>::UintMod::new(rho, pk.precomputed_modulus());
        let omega = (r * rho_mod.pow_signed_vartime(&e)).retrieve();

        Self {
            cap_s,
            cap_t,
            cap_a,
            gamma,
            z1,
            z2,
            omega,
        }
    }

    pub fn verify(
        &self,
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>, // $N$
        x: &Scalar,                                     // $x = y \mod q$
        cap_c: &Ciphertext<P::Paillier>,                // $C = enc(y, \rho)$
        aux_rp: &RPParamsMod<P::Paillier>,              // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> bool {
        let mut aux_rng = Hash::new_with_dst(b"P_enc").chain(aux).finalize_to_rng();
        let e = Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // enc(z_1, \omega) == A (+) C (*) e
        if Ciphertext::new_with_randomizer_signed(pk, &self.z1, &self.omega)
            != self
                .cap_a
                .homomorphic_add(pk, &cap_c.homomorphic_mul(pk, &e))
        {
            return false;
        }

        // z_1 == \gamma + e x \mod q
        if self.z1.to_scalar() != self.gamma + e.to_scalar() * *x {
            return false;
        }

        // s^{z_1} t^{z_2} == T S^e
        let cap_s_mod = self.cap_s.to_mod(aux_rp.public_key());
        let cap_t_mod = self.cap_t.to_mod(aux_rp.public_key());
        if aux_rp.commit(&self.z2, &self.z1) != &cap_t_mod * &cap_s_mod.pow_signed(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::DecProof;
    use crate::cggmp21::{SchemeParams, TestParams};
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

        // +10 to imitate a realistic bound
        // (sum_j(x_i * y_i) where x_i and y_j are bounded by L_BOUND)
        let y = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND * 2 + 10).abs_bounded();
        let x = y.to_scalar();

        let rho = Ciphertext::<Paillier>::randomizer(&mut OsRng, pk);
        let cap_c = Ciphertext::new_with_randomizer_bounded(pk, &y, &rho);

        let proof = DecProof::<Params>::random(&mut OsRng, &y, &rho, pk, &aux_rp, &aux);
        assert!(proof.verify(pk, &x, &cap_c, &aux_rp, &aux));
    }
}
