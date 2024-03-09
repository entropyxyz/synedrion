use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::{Add, Mul};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::curve::{Point, Scalar};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShareIdx(Scalar);

impl ShareIdx {
    pub fn new(idx: usize) -> Self {
        Self(Scalar::from(idx))
    }
}

pub(crate) fn shamir_evaluation_points(num_shares: usize) -> Vec<ShareIdx> {
    // For now we are hardcoding the points to be 1, 2, ..., n.
    // Potentially we can derive them from Session ID.
    (1..=u32::try_from(num_shares).expect("The number of shares cannot be over 2^32-1"))
        .map(|idx| ShareIdx(Scalar::from(idx)))
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

pub(crate) struct Polynomial(Vec<Scalar>);

impl Polynomial {
    pub fn random(rng: &mut impl CryptoRngCore, coeff0: &Scalar, degree: usize) -> Self {
        let mut coeffs = Vec::with_capacity(degree);
        coeffs.push(*coeff0);
        for _ in 1..degree {
            coeffs.push(Scalar::random_nonzero(rng));
        }
        Self(coeffs)
    }

    pub fn evaluate(&self, x: &ShareIdx) -> Scalar {
        evaluate_polynomial(&self.0, &x.0)
    }

    pub fn public(&self) -> PublicPolynomial {
        PublicPolynomial(
            self.0
                .iter()
                .map(|coeff| coeff.mul_by_generator())
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PublicPolynomial(Vec<Point>);

impl PublicPolynomial {
    pub fn evaluate(&self, x: &ShareIdx) -> Point {
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
    indices: &[ShareIdx],
) -> BTreeMap<ShareIdx, Scalar> {
    let polynomial = Polynomial::random(rng, secret, threshold);
    indices
        .iter()
        .map(|idx| (*idx, polynomial.evaluate(idx)))
        .collect()
}

pub(crate) fn interpolation_coeff(idxs: &[ShareIdx], exclude_idx: &ShareIdx) -> Scalar {
    idxs.iter()
        .filter(|idx| idx != &exclude_idx)
        .map(|idx| idx.0 * (idx.0 - exclude_idx.0).invert().unwrap())
        .product()
}

pub(crate) fn shamir_join_scalars<'a>(
    pairs: impl Iterator<Item = (&'a ShareIdx, &'a Scalar)>,
) -> Scalar {
    let (share_idxs, values): (Vec<_>, Vec<_>) = pairs.map(|(k, v)| (*k, *v)).unzip();
    values
        .iter()
        .enumerate()
        .map(|(i, val)| val * &interpolation_coeff(&share_idxs, &share_idxs[i]))
        .sum()
}

pub(crate) fn shamir_join_points<'a>(
    pairs: impl Iterator<Item = (&'a ShareIdx, &'a Point)>,
) -> Point {
    let (share_idxs, values): (Vec<_>, Vec<_>) = pairs.map(|(k, v)| (*k, *v)).unzip();
    values
        .iter()
        .enumerate()
        .map(|(i, val)| val * &interpolation_coeff(&share_idxs, &share_idxs[i]))
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
        let coeffs = (0..4)
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<_>>();

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

        let recovered_secret = shamir_join_scalars(shares.iter());
        assert_eq!(recovered_secret, secret);
    }
}
