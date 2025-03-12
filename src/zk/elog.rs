//! Dlog with El-Gamal Commitment ($\Pi^{elog}$, Section A.1, Fig. 23)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar},
    params::SchemeParams,
    tools::{
        hashing::{Chain, Hashable, Hasher},
        Secret,
    },
};

const HASH_TAG: &[u8] = b"P_elog";

pub(crate) struct ElogSecretInputs<'a, P: SchemeParams> {
    pub y: &'a Secret<Scalar<P>>,
    pub lambda: &'a Secret<Scalar<P>>,
}

#[derive(Clone, Copy)]
pub(crate) struct ElogPublicInputs<'a, P: SchemeParams> {
    /// Point $L = g * \lambda$, where $g$ is the curve generator.
    pub cap_l: &'a Point<P>,
    /// Point $M = g * y + X * \lambda$, where $g$ is the curve generator.
    pub cap_m: &'a Point<P>,
    /// Point $X$, satisfying the condition above.
    pub cap_x: &'a Point<P>,
    /// Point $Y = h * y$.
    pub cap_y: &'a Point<P>,
    /// Point $h$, satisfying the condition above.
    pub h: &'a Point<P>,
}

/// ZK proof: Paillier decryption modulo $q$.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "
    Scalar<P>: for<'x> Deserialize<'x>,
    Point<P>: for<'x> Deserialize<'x>
"))]
pub(crate) struct ElogProof<P: SchemeParams> {
    e: Scalar<P>,
    cap_a: Point<P>,
    cap_n: Point<P>,
    cap_b: Point<P>,
    z: Scalar<P>,
    u: Scalar<P>,
}

impl<P: SchemeParams> ElogProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        secret: ElogSecretInputs<'_, P>,
        public: ElogPublicInputs<'_, P>,
        aux: &impl Hashable,
    ) -> Self {
        let alpha = Secret::init_with(|| Scalar::random(rng));
        let m = Secret::init_with(|| Scalar::random(rng));

        let cap_a = alpha.mul_by_generator();
        let cap_n = m.mul_by_generator() + public.cap_x * &alpha;
        let cap_b = public.h * &m;

        let mut reader = Hasher::<P>::new_with_dst(HASH_TAG)
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
        }
    }

    pub fn verify(&self, public: ElogPublicInputs<'_, P>, aux: &impl Hashable) -> bool {
        let mut reader = Hasher::<P>::new_with_dst(HASH_TAG)
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
    use manul::{dev::BinaryFormat, session::WireFormat};
    use rand_core::OsRng;

    use super::{ElogProof, ElogPublicInputs, ElogSecretInputs};
    use crate::{curve::Scalar, dev::TestParams, tools::Secret};

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

        let secret = ElogSecretInputs { y: &y, lambda: &lambda };
        let public = ElogPublicInputs {
            cap_l: &cap_l,
            cap_m: &cap_m,
            cap_x: &cap_x,
            cap_y: &cap_y,
            h: &h,
        };

        let proof = ElogProof::<Params>::new(&mut OsRng, secret, public, &aux);

        // Serialization roundtrip
        let serialized = BinaryFormat::serialize(proof).unwrap();
        let proof = BinaryFormat::deserialize::<ElogProof<Params>>(&serialized).unwrap();

        assert!(proof.verify(public, &aux));
    }
}
