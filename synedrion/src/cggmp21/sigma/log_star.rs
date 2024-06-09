//! Knowledge of Exponent vs Paillier Encryption ($\Pi^{log*}$, Section C.2, Fig. 25)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::curve::Point;
use crate::paillier::{
    Ciphertext, CiphertextMod, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment,
    RPParamsMod, Randomizer, RandomizerMod,
};
use crate::tools::hashing::{Chain, Hashable, XofHasher};
use crate::uint::Signed;

const HASH_TAG: &[u8] = b"P_log*";

/**
ZK proof: Knowledge of Exponent vs Paillier Encryption.

Secret inputs:
- $x \in \pm 2^\ell$,
- $\rho$, a Paillier randomizer for the public key $N_0$.

Public inputs:
- Paillier public key $N_0$,
- Paillier ciphertext $C = enc_0(x, \rho)$,
- Point $g$,
- Point $X = g * x$,
- Setup parameters ($\hat{N}$, $s$, $t$).
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LogStarProof<P: SchemeParams> {
    e: Signed<<P::Paillier as PaillierParams>::Uint>,
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
    pub fn new(
        rng: &mut impl CryptoRngCore,
        x: &Signed<<P::Paillier as PaillierParams>::Uint>,
        rho: &RandomizerMod<P::Paillier>,
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_c: &CiphertextMod<P::Paillier>,
        g: &Point,
        cap_x: &Point,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        x.assert_bound(P::L_BOUND);
        assert_eq!(cap_c.public_key(), pk0);

        let hat_cap_n = &setup.public_key().modulus_bounded(); // $\hat{N}$

        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let r = RandomizerMod::random(rng, pk0);
        let gamma = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let cap_s = setup.commit(x, &mu).retrieve();
        let cap_a =
            CiphertextMod::new_with_randomizer_signed(pk0, &alpha, &r.retrieve()).retrieve();
        let cap_y = g * &P::scalar_from_signed(&alpha);
        let cap_d = setup.commit(&alpha, &gamma).retrieve();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_s)
            .chain(&cap_a)
            .chain(&cap_y)
            .chain(&cap_d)
            // public parameters
            .chain(pk0.as_minimal())
            .chain(&cap_c.retrieve())
            .chain(g)
            .chain(cap_x)
            .chain(&setup.retrieve())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = alpha + e * x;
        let z2 = (r * rho.pow_signed_vartime(&e)).retrieve();
        let z3 = gamma + mu * e.into_wide();

        Self {
            e,
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
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_c: &CiphertextMod<P::Paillier>,
        g: &Point,
        cap_x: &Point,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(cap_c.public_key(), pk0);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_s)
            .chain(&self.cap_a)
            .chain(&self.cap_y)
            .chain(&self.cap_d)
            // public parameters
            .chain(pk0.as_minimal())
            .chain(&cap_c.retrieve())
            .chain(g)
            .chain(cap_x)
            .chain(&setup.retrieve())
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

        // enc_0(z1, z2) == A (+) C (*) e
        let c = CiphertextMod::new_with_randomizer_signed(pk0, &self.z1, &self.z2);
        if c != self.cap_a.to_mod(pk0) + cap_c * e {
            return false;
        }

        // g^{z_1} == Y X^e
        if g * &P::scalar_from_signed(&self.z1) != self.cap_y + cap_x * &P::scalar_from_signed(&e) {
            return false;
        }

        // s^{z_1} t^{z_3} == D S^e \mod \hat{N}
        let cap_d_mod = self.cap_d.to_mod(setup.public_key());
        let cap_s_mod = self.cap_s.to_mod(setup.public_key());
        if setup.commit(&self.z1, &self.z3) != &cap_d_mod * &cap_s_mod.pow_signed_vartime(&e) {
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
    use crate::paillier::{CiphertextMod, RPParamsMod, RandomizerMod, SecretKeyPaillier};
    use crate::uint::Signed;

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let aux_sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let setup = RPParamsMod::random(&mut OsRng, &aux_sk);

        let aux: &[u8] = b"abcde";

        let g = Point::GENERATOR * Scalar::random(&mut OsRng);
        let x = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let rho = RandomizerMod::random(&mut OsRng, pk);
        let cap_c = CiphertextMod::new_with_randomizer_signed(pk, &x, &rho.retrieve());
        let cap_x = g * Params::scalar_from_signed(&x);

        let proof =
            LogStarProof::<Params>::new(&mut OsRng, &x, &rho, pk, &cap_c, &g, &cap_x, &setup, &aux);
        assert!(proof.verify(pk, &cap_c, &g, &cap_x, &setup, &aux));
    }
}
