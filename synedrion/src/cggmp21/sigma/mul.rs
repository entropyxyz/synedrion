//! Paillier multiplication ($\Pi^{mul}$, Section C.6, Fig. 29)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::{
    paillier::{Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, Randomizer},
    tools::{
        hashing::{Chain, Hashable, XofHasher},
        Secret,
    },
    uint::{Bounded, Signed},
};

const HASH_TAG: &[u8] = b"P_mul";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MulProof<P: SchemeParams> {
    e: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_a: CiphertextWire<P::Paillier>,
    cap_b: CiphertextWire<P::Paillier>,
    z: Signed<<P::Paillier as PaillierParams>::WideUint>,
    u: MaskedRandomizer<P::Paillier>,
    v: MaskedRandomizer<P::Paillier>,
}

/**
ZK proof: Paillier multiplication.

Secret inputs:
- $x$ (technically any integer since it will be implicitly reduced modulo $q$ or $\phi(N)$,
  but we limit its size to `Uint` since that's what we use in this library),
- $\rho_x$, a Paillier randomizer for the public key $N$,
- $\rho$, a Paillier randomizer for the public key $N$.

Public inputs:
- Paillier public key $N$,
- Paillier ciphertext $X = enc(x, \rho_x)$,
- Paillier ciphertext $Y$ encrypted with $N$,
- Paillier ciphertext $C = (Y (*) x) * \rho^N \mod N^2$,
- Setup parameters ($\hat{N}$, $s$, $t$).
*/
impl<P: SchemeParams> MulProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        x: &Secret<Signed<<P::Paillier as PaillierParams>::Uint>>,
        rho_x: &Randomizer<P::Paillier>,
        rho: &Randomizer<P::Paillier>,
        pk: &PublicKeyPaillier<P::Paillier>,
        cap_x: &Ciphertext<P::Paillier>,
        cap_y: &Ciphertext<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        assert_eq!(cap_x.public_key(), pk);
        assert_eq!(cap_y.public_key(), pk);
        assert_eq!(cap_c.public_key(), pk);

        let alpha_uint = Secret::init_with(|| pk.random_invertible_residue(rng));
        let alpha = Secret::init_with(|| {
            Bounded::new(
                *alpha_uint.expose_secret(),
                <P::Paillier as PaillierParams>::MODULUS_BITS,
            )
            .expect("the value is bounded by `MODULUS_BITS` by construction")
        });

        let r = Randomizer::random(rng, pk);
        let s = Randomizer::random(rng, pk);

        let cap_a = (cap_y * &alpha).mul_randomizer(&r).to_wire();
        let cap_b = Ciphertext::new_with_randomizer_bounded(pk, &alpha, &s).to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_a)
            .chain(&cap_b)
            // public parameters
            .chain(pk.as_wire())
            .chain(&cap_x.to_wire())
            .chain(&cap_y.to_wire())
            .chain(&cap_c.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z = *(alpha
            .to_wide()
            .to_signed()
            .expect("conversion to `WideUint` provides enough space for a sign bit")
            + x.mul_wide(&e))
        .expose_secret();
        let u = rho.to_masked(&r, &e);
        let v = rho_x.to_masked(&s, &e);

        Self {
            e,
            cap_a,
            cap_b,
            z,
            u,
            v,
        }
    }

    pub fn verify(
        &self,
        pk: &PublicKeyPaillier<P::Paillier>,
        cap_x: &Ciphertext<P::Paillier>,
        cap_y: &Ciphertext<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(cap_x.public_key(), pk);
        assert_eq!(cap_y.public_key(), pk);
        assert_eq!(cap_c.public_key(), pk);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_a)
            .chain(&self.cap_b)
            // public parameters
            .chain(pk.as_wire())
            .chain(&cap_x.to_wire())
            .chain(&cap_y.to_wire())
            .chain(&cap_c.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // Y^z u^N = A * C^e \mod N^2
        if cap_y.homomorphic_mul_wide(&self.z).mul_masked_randomizer(&self.u)
            != self.cap_a.to_precomputed(pk) + cap_c * e
        {
            return false;
        }

        // enc(z, v) == B * X^e \mod N^2
        // (Note: typo in the paper, it uses `c` and not `v` here)
        if Ciphertext::new_public_with_randomizer_wide(pk, &self.z, &self.v)
            != self.cap_b.to_precomputed(pk) + cap_x * e
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
    use crate::{
        cggmp21::{SchemeParams, TestParams},
        paillier::{Ciphertext, Randomizer, SecretKeyPaillierWire},
        tools::Secret,
        uint::Signed,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let aux: &[u8] = b"abcde";

        let x = Secret::init_with(|| Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND));
        let y = Secret::init_with(|| Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND));
        let rho_x = Randomizer::random(&mut OsRng, pk);
        let rho = Randomizer::random(&mut OsRng, pk);

        let cap_x = Ciphertext::new_with_randomizer_signed(pk, &x, &rho_x);
        let cap_y = Ciphertext::new_signed(&mut OsRng, pk, &y);
        let cap_c = (&cap_y * &x).mul_randomizer(&rho);

        let proof = MulProof::<Params>::new(&mut OsRng, &x, &rho_x, &rho, pk, &cap_x, &cap_y, &cap_c, &aux);
        assert!(proof.verify(pk, &cap_x, &cap_y, &cap_c, &aux));
    }
}
