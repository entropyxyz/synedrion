//! Paillier multiplication ($\Pi^{mul}$, Section C.6, Fig. 29)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{conversion::public_signed_from_scalar, SchemeParams};
use crate::{
    curve::Scalar,
    paillier::{Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, Randomizer},
    tools::{
        hashing::{Chain, Hashable, XofHasher},
        Secret,
    },
    uint::{PublicSigned, SecretSigned, SecretUnsigned},
};

const HASH_TAG: &[u8] = b"P_mul";

pub(crate) struct MulSecretInputs<'a, P: SchemeParams> {
    /// $x$ (technically any integer since it will be implicitly reduced modulo $q$ or $\phi(N)$,
    /// but we limit its size to `Uint` since that's what we use in this library).
    pub x: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $\rho_x$, a Paillier randomizer for the public key $N$.
    pub rho_x: &'a Randomizer<P::Paillier>,
    /// $\rho$, a Paillier randomizer for the public key $N$.
    pub rho: &'a Randomizer<P::Paillier>,
}

pub(crate) struct MulPublicInputs<'a, P: SchemeParams> {
    /// Paillier public key $N$.
    pub pk: &'a PublicKeyPaillier<P::Paillier>,
    /// Paillier ciphertext $X = enc(x, \rho_x)$.
    pub cap_x: &'a Ciphertext<P::Paillier>,
    /// Paillier ciphertext $Y$ encrypted with $N$.
    pub cap_y: &'a Ciphertext<P::Paillier>,
    /// Paillier ciphertext $C = (Y (*) x) * \rho^N \mod N^2$.
    pub cap_c: &'a Ciphertext<P::Paillier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MulProof<P: SchemeParams> {
    e: Scalar,
    cap_a: CiphertextWire<P::Paillier>,
    cap_b: CiphertextWire<P::Paillier>,
    z: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    u: MaskedRandomizer<P::Paillier>,
    v: MaskedRandomizer<P::Paillier>,
}

/// ZK proof: Paillier multiplication.
impl<P: SchemeParams> MulProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: MulSecretInputs<'_, P>,
        public: MulPublicInputs<'_, P>,
        aux: &impl Hashable,
    ) -> Self {
        assert_eq!(public.cap_x.public_key(), public.pk);
        assert_eq!(public.cap_y.public_key(), public.pk);
        assert_eq!(public.cap_c.public_key(), public.pk);

        let alpha_uint = Secret::init_with(|| public.pk.random_invertible_residue(rng));
        let alpha = SecretUnsigned::new(alpha_uint, <P::Paillier as PaillierParams>::MODULUS_BITS)
            .expect("the value is bounded by `MODULUS_BITS` by construction");

        let r = Randomizer::random(rng, public.pk);
        let s = Randomizer::random(rng, public.pk);

        let cap_a = (public.cap_y * &alpha).mul_randomizer(&r).to_wire();
        let cap_b = Ciphertext::new_with_randomizer_unsigned(public.pk, &alpha, &s).to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_a)
            .chain(&cap_b)
            // public parameters
            .chain(public.pk.as_wire())
            .chain(&public.cap_x.to_wire())
            .chain(&public.cap_y.to_wire())
            .chain(&public.cap_c.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e_scalar = Scalar::from_xof_reader(&mut reader);
        let e = public_signed_from_scalar::<P>(&e_scalar);

        let z = (alpha
            .to_wide()
            .into_signed()
            .expect("conversion to `WideUint` provides enough space for a sign bit")
            + secret.x.mul_wide(&e))
        .to_public();
        let u = secret.rho.to_masked(&r, &e);
        let v = secret.rho_x.to_masked(&s, &e);

        Self {
            e: e_scalar,
            cap_a,
            cap_b,
            z,
            u,
            v,
        }
    }

    pub fn verify(&self, public: MulPublicInputs<'_, P>, aux: &impl Hashable) -> bool {
        assert_eq!(public.cap_x.public_key(), public.pk);
        assert_eq!(public.cap_y.public_key(), public.pk);
        assert_eq!(public.cap_c.public_key(), public.pk);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_a)
            .chain(&self.cap_b)
            // public parameters
            .chain(public.pk.as_wire())
            .chain(&public.cap_x.to_wire())
            .chain(&public.cap_y.to_wire())
            .chain(&public.cap_c.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e_scalar = Scalar::from_xof_reader(&mut reader);

        if e_scalar != self.e {
            return false;
        }

        let e = public_signed_from_scalar::<P>(&e_scalar);

        // Y^z u^N = A * C^e \mod N^2
        if (public.cap_y * &self.z).mul_masked_randomizer(&self.u)
            != self.cap_a.to_precomputed(public.pk) + public.cap_c * &e
        {
            return false;
        }

        // enc(z, v) == B * X^e \mod N^2
        // (Note: typo in the paper, it uses `c` and not `v` here)
        if Ciphertext::new_public_with_randomizer_wide(public.pk, &self.z, &self.v)
            != self.cap_b.to_precomputed(public.pk) + public.cap_x * &e
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{MulProof, MulPublicInputs, MulSecretInputs};
    use crate::{
        cggmp21::{SchemeParams, TestParams},
        paillier::{Ciphertext, Randomizer, SecretKeyPaillierWire},
        uint::SecretSigned,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(&mut OsRng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(&mut OsRng, Params::L_BOUND);
        let rho_x = Randomizer::random(&mut OsRng, pk);
        let rho = Randomizer::random(&mut OsRng, pk);

        let cap_x = Ciphertext::new_with_randomizer(pk, &x, &rho_x);
        let cap_y = Ciphertext::new(&mut OsRng, pk, &y);
        let cap_c = (&cap_y * &x).mul_randomizer(&rho);

        let proof = MulProof::<Params>::new(
            &mut OsRng,
            MulSecretInputs {
                x: &x,
                rho_x: &rho_x,
                rho: &rho,
            },
            MulPublicInputs {
                pk,
                cap_x: &cap_x,
                cap_y: &cap_y,
                cap_c: &cap_c,
            },
            &aux,
        );
        assert!(proof.verify(
            MulPublicInputs {
                pk,
                cap_x: &cap_x,
                cap_y: &cap_y,
                cap_c: &cap_c
            },
            &aux
        ));
    }
}
