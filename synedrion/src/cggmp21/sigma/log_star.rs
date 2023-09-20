//! Knowledge of Exponent vs Paillier Encryption ($\Pi^{log*}$, Section C.2, Fig. 25)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::curve::Point;
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment, RPParamsMod,
    Randomizer, RandomizerMod,
};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::uint::{FromScalar, NonZero, Signed};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LogStarProof<P: SchemeParams> {
    cap_s: RPCommitment<P::Paillier>,
    cap_a: Ciphertext<P::Paillier>,
    cap_y: Point,
    cap_d: RPCommitment<P::Paillier>,
    z1: Signed<<P::Paillier as PaillierParams>::Uint>,
    z2: Randomizer<P::Paillier>,
    z3: Signed<<P::Paillier as PaillierParams>::WideUint>,
}

impl<P: SchemeParams> LogStarProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn random(
        rng: &mut impl CryptoRngCore,
        x: &Signed<<P::Paillier as PaillierParams>::Uint>, // $x \in +- 2^\ell$                                 // `x`
        rho: &RandomizerMod<P::Paillier>,                  // $\rho$
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>,    // $N_0$
        g: &Point,                                         // $g$
        aux_rp: &RPParamsMod<P::Paillier>,                 // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> Self {
        // TODO: check ranges of input values

        let mut aux_rng = Hash::new_with_dst(b"P_log*").chain(aux).finalize_to_rng();

        let hat_cap_n = &aux_rp.public_key().modulus_nonzero(); // $\hat{N}$

        // \alpha <-- +- 2^{\ell + \eps}
        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);

        // \mu <-- (+- 2^\ell) \hat{N}
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        // r <-- Z^*_{N_0}
        let r = RandomizerMod::random(rng, pk);

        // \gamma <-- (+- 2^{\ell + \eps}) \hat{N}
        let gamma = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        // S = s^x t^m  \mod \hat{N}
        let cap_s = aux_rp.commit(&mu, x).retrieve();

        // A = (1 + N_0)^\alpha r^N_0 \mod N_0^2
        let cap_a = Ciphertext::new_with_randomizer_signed(pk, &alpha, &r.retrieve());

        // Y = g^\alpha
        let cap_y = g * &alpha.to_scalar();

        // D = s^\alpha t^\gamma \mod \hat{N}
        let cap_d = aux_rp.commit(&gamma, &alpha).retrieve();

        // Non-interactive challenge ($e$)
        let challenge =
            Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // z_1 = \alpha + e x
        let z1 = alpha + challenge * *x;

        // z_2 = r * \rho^e mod N_0
        let z2 = (r * rho.pow_signed(&challenge)).retrieve();

        // z_3 = \gamma + e * \mu
        let z3 = gamma + mu * challenge.into_wide();

        Self {
            cap_s,
            cap_a,
            cap_y,
            cap_d,
            z1,
            z2,
            z3,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,   // $C = encrypt(x, \rho)$
        g: &Point,                         // $g$
        cap_x: &Point,                     // $X = g^x$
        aux_rp: &RPParamsMod<P::Paillier>, // $s$, $t$
        aux: &impl Hashable,
    ) -> bool {
        let mut aux_rng = Hash::new_with_dst(b"P_log*").chain(aux).finalize_to_rng();

        let challenge =
            Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // Check that $encrypt_{N_0}(z1, z2) == A (+) C (*) e$
        let c = Ciphertext::new_with_randomizer_signed(pk, &self.z1, &self.z2);

        if c != self
            .cap_a
            .homomorphic_add(pk, &cap_c.homomorphic_mul(pk, &challenge))
        {
            return false;
        }

        // g^{z_1} = Y X^e
        if g * &self.z1.to_scalar() != self.cap_y + cap_x * &challenge.to_scalar() {
            return false;
        }

        // Check that $s^{z_1} t^{z_3} == D S^e \mod \hat{N}$
        let cap_d_mod = self.cap_d.to_mod(aux_rp.public_key());
        let cap_s_mod = self.cap_s.to_mod(aux_rp.public_key());
        if aux_rp.commit(&self.z3, &self.z1)
            != &cap_d_mod * &cap_s_mod.pow_signed_vartime(&challenge)
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::LogStarProof;
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::curve::{Point, Scalar};
    use crate::paillier::{Ciphertext, RPParamsMod, RandomizerMod, SecretKeyPaillier};
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

        let g = &Point::GENERATOR * &Scalar::random(&mut OsRng);
        let x = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let rho = RandomizerMod::random(&mut OsRng, pk);
        let cap_c = Ciphertext::new_with_randomizer_signed(pk, &x, &rho.retrieve());
        let cap_x = &g * &x.to_scalar();

        let proof = LogStarProof::<Params>::random(&mut OsRng, &x, &rho, pk, &g, &aux_rp, &aux);
        assert!(proof.verify(pk, &cap_c, &g, &cap_x, &aux_rp, &aux));
    }
}
