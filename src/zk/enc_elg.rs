//! Range Proof w/ EL-Gamal Commitment ($\Pi^{enc-elg}$, Section A.2, Fig. 24)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar},
    paillier::{
        Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams,
        Randomizer,
    },
    protocols::conversion::{public_signed_from_scalar, scalar_from_signed, secret_scalar_from_signed},
    tools::{
        hashing::{Chain, Hashable, XofHasher},
        Secret,
    },
    uint::{PublicSigned, SecretSigned},
    SchemeParams,
};

const HASH_TAG: &[u8] = b"P_enc_elg";

pub struct EncElgSecretInputs<'a, P: SchemeParams> {
    /// $x ∈ ±2^\ell$.
    pub x: &'a SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    /// $\rho$, a Paillier randomizer for the public key $N_0$.
    pub rho: &'a Randomizer<P::Paillier>,
    /// Scalar $b$.
    pub b: &'a Secret<Scalar<P>>,
}

#[derive(Clone, Copy)]
pub struct EncElgPublicInputs<'a, P: SchemeParams> {
    /// Paillier public key $N_0$.
    pub pk0: &'a PublicKeyPaillier<P::Paillier>,
    /// Paillier ciphertext $C = enc_0(x, \rho)$.
    pub cap_c: &'a Ciphertext<P::Paillier>,
    /// Point $A = g^a$, where $g$ is the curve generator.
    pub cap_a: &'a Point<P>,
    /// Point $B = g^b$, where $g$ is the curve generator.
    pub cap_b: &'a Point<P>,
    /// Point $X = g^(a b + x)$, where $g$ is the curve generator.
    pub cap_x: &'a Point<P>,
}

/// ZK proof: Paillier encryption in range.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "
    Scalar<P>: for<'x> Deserialize<'x>,
    Point<P>: for<'x> Deserialize<'x>
"))]
pub(crate) struct EncElgProof<P: SchemeParams> {
    e: Scalar<P>,
    cap_s: RPCommitmentWire<P::Paillier>,
    cap_d: CiphertextWire<P::Paillier>,
    cap_y: Point<P>,
    cap_z: Point<P>,
    cap_t: RPCommitmentWire<P::Paillier>,
    z1: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    w: Scalar<P>,
    z2: MaskedRandomizer<P::Paillier>,
    z3: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
}

impl<P: SchemeParams> EncElgProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: EncElgSecretInputs<'_, P>,
        public: EncElgPublicInputs<'_, P>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        secret.x.assert_exponent_range(P::L_BOUND);
        assert_eq!(public.cap_c.public_key(), public.pk0);

        let hat_cap_n = setup.modulus(); // $\hat{N}$

        let alpha = SecretSigned::random_in_exponent_range(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND, hat_cap_n);
        let r = Randomizer::random(rng, public.pk0);
        let beta = Secret::init_with(|| Scalar::random(rng));
        let gamma = SecretSigned::random_in_exponent_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let cap_s = setup.commit(secret.x, &mu).to_wire();
        let cap_d = Ciphertext::new_with_randomizer(public.pk0, &alpha, &r).to_wire();
        let cap_y = public.cap_a * &beta + secret_scalar_from_signed::<P>(&alpha).mul_by_generator();
        let cap_z = beta.mul_by_generator();
        let cap_t = setup.commit(&alpha, &gamma).to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_s)
            .chain(&cap_d)
            .chain(&cap_y)
            .chain(&cap_z)
            .chain(&cap_t)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(&public.cap_a)
            .chain(&public.cap_b)
            .chain(&public.cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Scalar::from_xof_reader(&mut reader);
        let e_signed = public_signed_from_scalar::<P>(&e);

        let z1 = (alpha + secret.x * e_signed).to_public();
        let w = *(beta + secret.b * e).expose_secret();
        let z2 = secret.rho.to_masked(&r, &e_signed);
        let z3 = (gamma + mu * e_signed.to_wide()).to_public();

        Self {
            e,
            cap_s,
            cap_d,
            cap_y,
            cap_z,
            cap_t,
            z1,
            w,
            z2,
            z3,
        }
    }

    pub fn verify(
        &self,
        public: EncElgPublicInputs<'_, P>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(public.cap_c.public_key(), public.pk0);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_s)
            .chain(&self.cap_d)
            .chain(&self.cap_y)
            .chain(&self.cap_z)
            .chain(&self.cap_t)
            // public parameters
            .chain(public.pk0.as_wire())
            .chain(&public.cap_c.to_wire())
            .chain(&public.cap_a)
            .chain(&public.cap_b)
            .chain(&public.cap_x)
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Scalar::from_xof_reader(&mut reader);

        if e != self.e {
            return false;
        }

        let e_signed = public_signed_from_scalar::<P>(&e);

        // z_1 ∈ ±2^{\ell + \eps}
        if !self.z1.is_in_exponent_range(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        // enc_0(z_1, z_2) == D (+) C (*) e
        let c = Ciphertext::new_public_with_randomizer(public.pk0, &self.z1, &self.z2);
        let cap_d = self.cap_d.to_precomputed(public.pk0);
        if c != cap_d + public.cap_c * &e_signed {
            return false;
        }

        // A^w g^{z_1} == Y X^e
        if public.cap_a * self.w + scalar_from_signed::<P>(&self.z1).mul_by_generator() != self.cap_y + public.cap_x * e
        {
            return false;
        }

        // g^w == Z B^e
        if self.w.mul_by_generator() != self.cap_z + public.cap_b * e {
            return false;
        }

        // s^{z_1} t^{z_3} == T S^e \mod \hat{N}
        let cap_t = self.cap_t.to_precomputed(setup);
        let cap_s = self.cap_s.to_precomputed(setup);
        if setup.commit(&self.z1, &self.z3) != &cap_t * &cap_s.pow(&e_signed) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use manul::{dev::BinaryFormat, session::WireFormat};
    use rand_core::OsRng;

    use super::{EncElgProof, EncElgPublicInputs, EncElgSecretInputs};
    use crate::{
        curve::Scalar,
        dev::TestParams,
        paillier::{Ciphertext, RPParams, Randomizer, SecretKeyPaillierWire},
        protocols::{conversion::secret_scalar_from_signed, SchemeParams},
        tools::Secret,
        uint::SecretSigned,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let setup = RPParams::random(&mut OsRng);

        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(&mut OsRng, Params::L_BOUND);
        let rho = Randomizer::random(&mut OsRng, pk);
        let a = Secret::init_with(|| Scalar::random(&mut OsRng));
        let b = Secret::init_with(|| Scalar::random(&mut OsRng));

        let cap_c = Ciphertext::new_with_randomizer(pk, &x, &rho);
        let cap_a = a.mul_by_generator();
        let cap_b = b.mul_by_generator();
        let cap_x = (&a * &b + secret_scalar_from_signed::<Params>(&x)).mul_by_generator();

        let secret = EncElgSecretInputs {
            x: &x,
            rho: &rho,
            b: &b,
        };
        let public = EncElgPublicInputs {
            pk0: pk,
            cap_c: &cap_c,
            cap_a: &cap_a,
            cap_b: &cap_b,
            cap_x: &cap_x,
        };

        let proof = EncElgProof::<Params>::new(&mut OsRng, secret, public, &setup, &aux);

        // Serialization roundtrip
        let serialized = BinaryFormat::serialize(proof).unwrap();
        let proof = BinaryFormat::deserialize::<EncElgProof<Params>>(&serialized).unwrap();

        assert!(proof.verify(public, &setup, &aux));
    }
}
