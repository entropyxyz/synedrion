use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::ops::{Add, Mul};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{
    curve::{Point, Scalar},
    tools::HideDebug,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShareId(Scalar);

impl ShareId {
    pub fn new(idx: u64) -> Self {
        Self(Scalar::from(idx))
    }
}

pub(crate) fn shamir_evaluation_points(num_shares: usize) -> Vec<ShareId> {
    // For now we are hardcoding the points to be 1, 2, ..., n.
    // Potentially we can derive them from Session ID.
    (1..=u64::try_from(num_shares).expect("no more than 2^64-1 shares needed"))
        .map(|idx| ShareId(Scalar::from(idx)))
        .collect()
}

fn evaluate_polynomial<T>(coeffs: &[T], x: &Scalar) -> T
where
    T: Copy + Add<T, Output = T> + for<'a> Mul<&'a Scalar, Output = T>,
{
    // Evaluate in reverse to save on multiplications.
    // Basically: a0 + a1 x + a2 x^2 + a3 x^3 == (((a3 x) + a2) x + a1) x + a0
    let mut res = coeffs[coeffs.len() - 1];
    for i in (0..(coeffs.len() - 1)).rev() {
        res = res * x + coeffs[i];
    }
    res
}

#[derive(Debug, ZeroizeOnDrop)]
pub(crate) struct Polynomial(HideDebug<Vec<Scalar>>);

impl Polynomial {
    pub fn random(rng: &mut impl CryptoRngCore, coeff0: &Scalar, degree: usize) -> Self {
        let mut coeffs = Vec::with_capacity(degree);
        coeffs.push(*coeff0);
        for _ in 1..degree {
            coeffs.push(Scalar::random_nonzero(rng));
        }
        Self(coeffs.into())
    }

    pub fn evaluate(&self, x: &ShareId) -> Scalar {
        evaluate_polynomial(&self.0, &x.0)
    }

    pub fn public(&self) -> PublicPolynomial {
        PublicPolynomial(self.0.iter().map(|coeff| coeff.mul_by_generator()).collect())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PublicPolynomial(Vec<Point>);

impl PublicPolynomial {
    pub fn evaluate(&self, x: &ShareId) -> Point {
        evaluate_polynomial(&self.0, &x.0)
    }

    pub fn coeff0(&self) -> Point {
        self.0[0]
    }
}

pub(crate) fn shamir_split(
    rng: &mut impl CryptoRngCore,
    secret: &Scalar,
    threshold: usize,
    indices: &[ShareId],
) -> BTreeMap<ShareId, Scalar> {
    let polynomial = Polynomial::random(rng, secret, threshold);
    indices.iter().map(|idx| (*idx, polynomial.evaluate(idx))).collect()
}

pub(crate) fn interpolation_coeff(share_ids: &BTreeSet<ShareId>, share_id: &ShareId) -> Scalar {
    share_ids
        .iter()
        .filter(|id| id != &share_id)
        .map(|id| {
            id.0 * (id.0 - share_id.0)
                .invert()
                .expect("all share IDs are distinct as enforced by BTreeSet")
        })
        .product()
}

pub(crate) fn shamir_join_scalars(pairs: &BTreeMap<ShareId, Scalar>) -> Scalar {
    let share_ids = pairs.keys().cloned().collect::<BTreeSet<_>>();
    pairs
        .iter()
        .map(|(share_id, val)| val * &interpolation_coeff(&share_ids, share_id))
        .sum()
}

pub(crate) fn shamir_join_points(pairs: &BTreeMap<ShareId, Point>) -> Point {
    let share_ids = pairs.keys().cloned().collect::<BTreeSet<_>>();
    pairs
        .iter()
        .map(|(share_id, val)| val * &interpolation_coeff(&share_ids, share_id))
        .sum()
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{evaluate_polynomial, shamir_evaluation_points, shamir_join_scalars, shamir_split};
    use crate::curve::Scalar;

    #[test]
    fn evaluate() {
        let x = Scalar::random(&mut OsRng);
        let coeffs = (0..4).map(|_| Scalar::random(&mut OsRng)).collect::<Vec<_>>();

        let actual = evaluate_polynomial(&coeffs, &x);
        let expected = coeffs[0] + coeffs[1] * x + coeffs[2] * x * x + coeffs[3] * x * x * x;

        assert_eq!(actual, expected);
    }

    #[test]
    fn split_and_join() {
        let threshold = 3;
        let num_shares = 5;
        let secret = Scalar::random(&mut OsRng);
        let points = shamir_evaluation_points(num_shares);
        let mut shares = shamir_split(&mut OsRng, &secret, threshold, &points);

        shares.remove(&points[0]);
        shares.remove(&points[3]);

        let recovered_secret = shamir_join_scalars(&shares);
        assert_eq!(recovered_secret, secret);
    }
}
