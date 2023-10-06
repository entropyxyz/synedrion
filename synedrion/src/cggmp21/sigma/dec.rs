//! Paillier decryption modulo $q$ ($\Pi^{dec}$, Section C.6, Fig. 30)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::curve::Scalar;
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment, RPParamsMod,
    Randomizer, RandomizerMod,
};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::uint::{FromScalar, NonZero, Signed};

const HASH_TAG: &[u8] = b"P_dec";

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct DecProof<P: SchemeParams> {
    cap_s: RPCommitment<P::Paillier>,
    cap_t: RPCommitment<P::Paillier>,
    cap_a: Ciphertext<P::Paillier>,
    gamma: Scalar,
    z1: Signed<<P::Paillier as PaillierParams>::Uint>,
    z2: Signed<<P::Paillier as PaillierParams>::WideUint>,
    omega: Randomizer<P::Paillier>,
}

impl<P: SchemeParams> DecProof<P> {
    pub fn random(
        rng: &mut impl CryptoRngCore,
        y: &Signed<<P::Paillier as PaillierParams>::Uint>,
        rho: &RandomizerMod<P::Paillier>,
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>, // $N$
        aux_rp: &RPParamsMod<P::Paillier>,              // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> Self {
        let mut aux_rng = Hash::new_with_dst(HASH_TAG).chain(aux).finalize_to_rng();

        // Non-interactive challenge
        let e = Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        let hat_cap_n = &aux_rp.public_key().modulus_nonzero(); // $\hat{N}$

        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let nu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let r = RandomizerMod::random(rng, pk);

        let cap_s = aux_rp.commit(&mu, y).retrieve();
        let cap_t = aux_rp.commit(&nu, &alpha).retrieve();
        let cap_a = Ciphertext::new_with_randomizer_signed(pk, &alpha, &r.retrieve());
        let gamma = alpha.to_scalar();

        let z1 = alpha + e * *y;
        let z2 = nu + e.into_wide() * mu;

        let omega = (r * rho.pow_signed_vartime(&e)).retrieve();

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
        let mut aux_rng = Hash::new_with_dst(HASH_TAG).chain(aux).finalize_to_rng();

        // Non-interactive challenge
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
        if aux_rp.commit(&self.z2, &self.z1) != &cap_t_mod * &cap_s_mod.pow_signed_vartime(&e) {
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
    use crate::paillier::{
        Ciphertext, PaillierParams, RPParamsMod, RandomizerMod, SecretKeyPaillier,
    };
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

        // We need something within the range -N/2..N/2 so that it doesn't wrap around.
        let y = Signed::random_bounded_bits(&mut OsRng, Paillier::PRIME_BITS - 2);
        let x = y.to_scalar();

        let rho = RandomizerMod::random(&mut OsRng, pk);
        let cap_c = Ciphertext::new_with_randomizer_signed(pk, &y, &rho.retrieve());

        let proof = DecProof::<Params>::random(&mut OsRng, &y, &rho, pk, &aux_rp, &aux);
        assert!(proof.verify(pk, &x, &cap_c, &aux_rp, &aux));
    }
}