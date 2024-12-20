//! Dlog with El-Gamal Commitment ($\Pi^{elog}$, Section A.1, Fig. 23)

#![allow(dead_code)]

use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::{
    curve::{Point, Scalar},
    tools::{
        hashing::{Chain, Hashable, XofHasher},
        Secret,
    },
};

const HASH_TAG: &[u8] = b"P_elog";

pub(crate) struct ElogSecretInputs<'a> {
    pub y: &'a Secret<Scalar>,
    pub lambda: &'a Secret<Scalar>,
}

pub(crate) struct ElogPublicInputs<'a> {
    /// Point $L = g * \lambda$, where $g$ is the curve generator.
    pub cap_l: &'a Point,
    /// Point $M = g * y + X * \lambda$, where $g$ is the curve generator.
    pub cap_m: &'a Point,
    /// Point $X$, satisfying the condition above.
    pub cap_x: &'a Point,
    /// Point $Y = h * y$.
    pub cap_y: &'a Point,
    /// Point $h$, satisfying the condition above.
    pub h: &'a Point,
}

/// ZK proof: Paillier decryption modulo $q$.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ElogProof<P: SchemeParams> {
    e: Scalar,
    cap_a: Point,
    cap_n: Point,
    cap_b: Point,
    z: Scalar,
    u: Scalar,
    phantom: PhantomData<P>,
}

impl<P: SchemeParams> ElogProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: ElogSecretInputs<'_>,
        public: ElogPublicInputs<'_>,
        aux: &impl Hashable,
    ) -> Self {
        let alpha = Secret::init_with(|| Scalar::random(rng));
        let m = Secret::init_with(|| Scalar::random(rng));

        let cap_a = alpha.mul_by_generator();
        let cap_n = m.mul_by_generator() + public.cap_x * &alpha;
        let cap_b = public.h * &m;

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_a)
            .chain(&cap_n)
            .chain(&cap_b)
            // public parameters
            .chain(&public.cap_l)
            .chain(&public.cap_m)
            .chain(&public.cap_x)
            .chain(&public.cap_y)
            .chain(&public.h)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Scalar::from_xof_reader(&mut reader);

        let z = *(alpha + secret.lambda * e).expose_secret();
        let u = *(m + secret.y * e).expose_secret();

        Self {
            e,
            cap_a,
            cap_n,
            cap_b,
            z,
            u,
            phantom: PhantomData,
        }
    }

    pub fn verify(&self, public: ElogPublicInputs<'_>, aux: &impl Hashable) -> bool {
        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_a)
            .chain(&self.cap_n)
            .chain(&self.cap_b)
            // public parameters
            .chain(&public.cap_l)
            .chain(&public.cap_m)
            .chain(&public.cap_x)
            .chain(&public.cap_y)
            .chain(&public.h)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Scalar::from_xof_reader(&mut reader);

        if e != self.e {
            return false;
        }

        // g * z == A + L * e
        if self.z.mul_by_generator() != self.cap_a + public.cap_l * e {
            return false;
        }

        // g * u + X * z == N + M * e
        if self.u.mul_by_generator() + public.cap_x * self.z != self.cap_n + public.cap_m * e {
            return false;
        }

        // h * u == B + Y * e
        if public.h * self.u != self.cap_b + public.cap_y * e {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{ElogProof, ElogPublicInputs, ElogSecretInputs};
    use crate::{cggmp21::TestParams, curve::Scalar, tools::Secret};

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;

        let aux: &[u8] = b"abcde";

        let y = Secret::init_with(|| Scalar::random(&mut OsRng));
        let lambda = Secret::init_with(|| Scalar::random(&mut OsRng));

        let cap_l = lambda.mul_by_generator();
        let cap_x = Scalar::random(&mut OsRng).mul_by_generator();
        let cap_m = y.mul_by_generator() + cap_x * &lambda;
        let h = Scalar::random(&mut OsRng).mul_by_generator();
        let cap_y = h * &y;

        let proof = ElogProof::<Params>::new(
            &mut OsRng,
            ElogSecretInputs { y: &y, lambda: &lambda },
            ElogPublicInputs {
                cap_l: &cap_l,
                cap_m: &cap_m,
                cap_x: &cap_x,
                cap_y: &cap_y,
                h: &h,
            },
            &aux,
        );
        assert!(proof.verify(
            ElogPublicInputs {
                cap_l: &cap_l,
                cap_m: &cap_m,
                cap_x: &cap_x,
                cap_y: &cap_y,
                h: &h
            },
            &aux
        ));
    }
}
