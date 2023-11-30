//! Paillier multiplication ($\Pi^{mul}$, Section C.6, Fig. 29)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillierPrecomputed, Randomizer, RandomizerMod,
};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::{Bounded, NonZero, Retrieve, Signed};

const HASH_TAG: &[u8] = b"P_mul";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MulProof<P: SchemeParams> {
    cap_a: Ciphertext<P::Paillier>,
    cap_b: Ciphertext<P::Paillier>,
    z: Signed<<P::Paillier as PaillierParams>::WideUint>,
    u: Randomizer<P::Paillier>,
    v: Randomizer<P::Paillier>,
}

impl<P: SchemeParams> MulProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: &Signed<<P::Paillier as PaillierParams>::Uint>, // $x$
        rho_x_mod: &RandomizerMod<P::Paillier>,                 // $\rho_x$
        rho_mod: &RandomizerMod<P::Paillier>,                   // $\rho$
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>,         // $N$
        cap_y: &Ciphertext<P::Paillier>,                        // $Y$
        aux: &impl Hashable,
    ) -> Self {
        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e =
            Signed::from_xof_reader_bounded(&mut reader, &NonZero::new(P::CURVE_ORDER).unwrap());

        let alpha_mod = pk.random_invertible_group_elem(rng);
        let r_mod = RandomizerMod::random(rng, pk);
        let s_mod = RandomizerMod::random(rng, pk);

        let alpha = Bounded::new(
            alpha_mod.retrieve(),
            <P::Paillier as PaillierParams>::MODULUS_BITS as u32,
        )
        .unwrap();
        let r = r_mod.retrieve();
        let s = s_mod.retrieve();

        let cap_a = cap_y
            .homomorphic_mul_unsigned(pk, &alpha)
            .mul_randomizer(pk, &r);
        let cap_b = Ciphertext::new_with_randomizer(pk, alpha.as_ref(), &s);

        let z = alpha.into_wide().into_signed().unwrap() + e.mul_wide(secret);
        let u = (r_mod * rho_mod.pow_signed_vartime(&e)).retrieve();
        let v = (s_mod * rho_x_mod.pow_signed_vartime(&e)).retrieve();

        Self {
            cap_a,
            cap_b,
            z,
            u,
            v,
        }
    }

    pub fn verify(
        &self,
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>, // $N$
        cap_x: &Ciphertext<P::Paillier>,                // $X = enc(x, \rho_x)$
        cap_y: &Ciphertext<P::Paillier>,                // $Y$
        cap_c: &Ciphertext<P::Paillier>,                // $C = (Y (*) x) * \rho^N$
        aux: &impl Hashable,
    ) -> bool {
        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e =
            Signed::from_xof_reader_bounded(&mut reader, &NonZero::new(P::CURVE_ORDER).unwrap());

        // Y^z u^N = A * C^e \mod N^2
        if cap_y
            .homomorphic_mul_wide(pk, &self.z)
            .mul_randomizer(pk, &self.u)
            != self
                .cap_a
                .homomorphic_add(pk, &cap_c.homomorphic_mul(pk, &e))
        {
            return false;
        }

        // enc(z, v) == B * X^e \mod N^2
        // (Note: typo in the paper, it uses `c` and not `v` here)
        if Ciphertext::new_with_randomizer_wide(pk, &self.z, &self.v)
            != self
                .cap_b
                .homomorphic_add(pk, &cap_x.homomorphic_mul(pk, &e))
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::MulProof;
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::paillier::{Ciphertext, RandomizerMod, SecretKeyPaillier};
    use crate::uint::Signed;

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let aux: &[u8] = b"abcde";

        let x = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let y = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let rho_x = RandomizerMod::random(&mut OsRng, pk);
        let rho = RandomizerMod::random(&mut OsRng, pk);

        let cap_x = Ciphertext::new_with_randomizer_signed(pk, &x, &rho_x.retrieve());
        let cap_y = Ciphertext::new_signed(&mut OsRng, pk, &y);
        let cap_c = cap_y
            .homomorphic_mul(pk, &x)
            .mul_randomizer(pk, &rho.retrieve());

        let proof = MulProof::<Params>::new(&mut OsRng, &x, &rho_x, &rho, pk, &cap_y, &aux);
        assert!(proof.verify(pk, &cap_x, &cap_y, &cap_c, &aux));
    }
}
