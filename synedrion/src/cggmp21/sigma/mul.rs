//! Paillier multiplication ($\Pi^{mul}$, Section C.6, Fig. 29)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{Ciphertext, PaillierParams, PublicKeyPaillierPrecomputed};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::uint::{Bounded, NonZero, Retrieve, Signed, UintModLike};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct MulProof<P: SchemeParams> {
    cap_a: Ciphertext<P::Paillier>,
    cap_b: Ciphertext<P::Paillier>,
    z: Signed<<P::Paillier as PaillierParams>::WideUint>,
    u: <P::Paillier as PaillierParams>::Uint,
    v: <P::Paillier as PaillierParams>::Uint,
}

impl<P: SchemeParams> MulProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn random(
        rng: &mut impl CryptoRngCore,
        secret: &Signed<<P::Paillier as PaillierParams>::Uint>, // $x$
        rho_x: &<P::Paillier as PaillierParams>::Uint,          // $\rho_x$
        rho_y: &<P::Paillier as PaillierParams>::Uint,          // the randomizer of $Y$
        rho_c: &<P::Paillier as PaillierParams>::Uint,          // the randomizer of $C$
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>,         // $N$
        cap_y: &Ciphertext<P::Paillier>,                        // $Y$
        aux: &impl Hashable,
    ) -> Self {
        let mut aux_rng = Hash::new_with_dst(b"P_mul").chain(aux).finalize_to_rng();

        /*
        CHECK: in Fig. 29, the proof takes three ciphertexts:
        $X = enc(x, \rho_x); Y; C = Y^x \rho^N$
        But at the stage where it is supposed to be used (Presigning, Round 3), what we have is
        $X = enc(x, \rho_x); Y = enc(y, \rho_y); C = enc(x * y, \rho_c)$
        So instead of taking $\rho$ as a parameter, we take $\rho_y$ and $\rho_z$ that we know
        and derive $\rho$ from them:
        $\rho = \rho_c * \rho_y^(-x)$
        Setting $\rho$ to this value will make $C$ have the desired relation to $x$ and $Y$.
        */
        let rho_c_mod =
            <P::Paillier as PaillierParams>::UintMod::new(rho_c, pk.precomputed_modulus());
        let rho_y_mod =
            <P::Paillier as PaillierParams>::UintMod::new(rho_y, pk.precomputed_modulus());
        let rho = (rho_c_mod * rho_y_mod.pow_signed(&-secret)).retrieve();

        let alpha_mod = pk.random_invertible_group_elem(rng);
        let r_mod = pk.random_invertible_group_elem(rng);
        let s_mod = pk.random_invertible_group_elem(rng);

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

        let e = Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        let z = alpha.into_signed().unwrap().into_wide() + e.mul_wide(secret);
        let rho_mod = <P::Paillier as PaillierParams>::UintMod::new(&rho, pk.precomputed_modulus());
        let rho_x_mod =
            <P::Paillier as PaillierParams>::UintMod::new(rho_x, pk.precomputed_modulus());
        let u = (r_mod * rho_mod.pow_signed(&e)).retrieve();
        let v = (s_mod * rho_x_mod.pow_signed(&e)).retrieve();

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
        let mut aux_rng = Hash::new_with_dst(b"P_mul").chain(aux).finalize_to_rng();

        let e = Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

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
    use crate::paillier::{Ciphertext, SecretKeyPaillier};
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
        let rho_x = Ciphertext::<Paillier>::randomizer(&mut OsRng, pk);
        let rho_y = Ciphertext::<Paillier>::randomizer(&mut OsRng, pk);
        let rho_c = Ciphertext::<Paillier>::randomizer(&mut OsRng, pk);

        let cap_x = Ciphertext::new_with_randomizer_signed(pk, &x, &rho_x);
        let cap_y = Ciphertext::new_with_randomizer_signed(pk, &y, &rho_y);
        let cap_c = Ciphertext::new_with_randomizer_signed(pk, &(x * y), &rho_c);

        let proof =
            MulProof::<Params>::random(&mut OsRng, &x, &rho_x, &rho_y, &rho_c, pk, &cap_y, &aux);
        assert!(proof.verify(pk, &cap_x, &cap_y, &cap_c, &aux));
    }
}
