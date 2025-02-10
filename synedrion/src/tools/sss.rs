use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::ops::{Add, Mul};
use manul::session::LocalError;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar},
    tools::Secret,
    SchemeParams,
};
use primeorder::elliptic_curve::CurveArithmetic;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShareId<P: SchemeParams>(Scalar<P>);

impl<P> ShareId<P>
where
    P: SchemeParams,
{
    pub fn new(idx: u64) -> Self {
        Self(Scalar::from(idx))
    }
}

pub(crate) fn shamir_evaluation_points<P>(num_shares: usize) -> Vec<ShareId<P>>
where
    P: SchemeParams,
{
    // For now we are hardcoding the points to be 1, 2, ..., n.
    // Potentially we can derive them from Session ID.
    (1..=u64::try_from(num_shares).expect("no more than 2^64-1 shares needed"))
        .map(|idx| ShareId(Scalar::from(idx)))
        .collect()
}

fn evaluate_polynomial<T, P>(coeffs: &[T], x: &Scalar<P>) -> T
where
    T: Copy + Add<T, Output = T> + for<'a> Mul<&'a Scalar<P>, Output = T> + Clone,
    P: SchemeParams,
{
    assert!(coeffs.len() > 1, "Expected coefficients to be non-empty");
    // Evaluate in reverse to save on multiplications.
    // Basically: a0 + a1 x + a2 x^2 + a3 x^3 == (((a3 x) + a2) x + a1) x + a0

    let (acc, coeffs) = coeffs.split_last().expect("Coefficients is not empty");
    coeffs.iter().rev().fold(*acc, |mut acc, coeff| {
        acc = acc * x + *coeff;
        acc
    })
}

fn evaluate_polynomial_secret<P>(coeffs: &[Secret<Scalar<P>>], x: &Scalar<P>) -> Secret<Scalar<P>>
where
    P: SchemeParams,
{
    // Evaluate in reverse to save on multiplications.
    // Basically: a0 + a1 x + a2 x^2 + a3 x^3 == (((a3 x) + a2) x + a1) x + a0
    let (acc, coeffs) = coeffs.split_last().expect("Coefficients is not empty");
    coeffs.iter().rev().fold(acc.clone(), |mut acc, coeff| {
        acc = acc * x + coeff.expose_secret();
        acc
    })
}

#[derive(Debug)]
pub(crate) struct Polynomial<P: SchemeParams>(Vec<Secret<Scalar<P>>>);

impl<P> Polynomial<P>
where
    P: SchemeParams,
{
    pub fn random(rng: &mut impl CryptoRngCore, coeff0: Secret<Scalar<P>>, degree: usize) -> Self {
        let mut coeffs = Vec::with_capacity(degree);
        coeffs.push(coeff0);
        for _ in 1..degree {
            coeffs.push(Secret::init_with(|| Scalar::random_nonzero(rng)));
        }
        Self(coeffs)
    }

    pub fn evaluate(&self, x: &ShareId<P>) -> Secret<Scalar<P>> {
        evaluate_polynomial_secret(&self.0, &x.0)
    }

    pub fn public(&self) -> PublicPolynomial<P> {
        PublicPolynomial(
            self.0
                .iter()
                .map(|coeff| coeff.expose_secret().mul_by_generator())
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PublicPolynomial<P: SchemeParams>(Vec<Point<P>>);

impl<P> PublicPolynomial<P>
where
    P: SchemeParams,
{
    pub fn evaluate(&self, x: &ShareId<P>) -> Point<P> {
        evaluate_polynomial(&self.0, &x.0)
    }

    pub fn coeff0(&self) -> Result<&Point<P>, LocalError> {
        self.0
            .first()
            .ok_or_else(|| LocalError::new("Invalid PublicPolynomial"))
    }
}

pub(crate) fn shamir_split<P>(
    rng: &mut impl CryptoRngCore,
    secret: Secret<Scalar<P>>,
    threshold: usize,
    indices: &[ShareId<P>],
) -> BTreeMap<ShareId<P>, Secret<Scalar<P>>>
where
    P: SchemeParams,
{
    let polynomial = Polynomial::random(rng, secret, threshold);
    indices
        .iter()
        .map(|idx| (idx.clone(), polynomial.evaluate(idx)))
        .collect()
}

pub(crate) fn interpolation_coeff<P>(share_ids: &BTreeSet<ShareId<P>>, share_id: &ShareId<P>) -> Scalar<P>
where
    P: SchemeParams,
    <P::Curve as CurveArithmetic>::Scalar: Copy,
{
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

pub(crate) fn shamir_join_scalars<P>(pairs: BTreeMap<ShareId<P>, Secret<Scalar<P>>>) -> Secret<Scalar<P>>
where
    P: SchemeParams,
{
    let share_ids = pairs.keys().cloned().collect::<BTreeSet<_>>();
    let mut sum = Secret::init_with(|| Scalar::ZERO);

    for (share_id, val) in pairs.into_iter() {
        sum += val * interpolation_coeff(&share_ids, &share_id);
    }

    sum
}

pub(crate) fn shamir_join_points<P>(pairs: &BTreeMap<ShareId<P>, Point<P>>) -> Point<P>
where
    P: SchemeParams,
{
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
    use crate::{curve::Scalar, tools::Secret, TestParams};

    #[test]
    fn evaluate() {
        let x = Scalar::<TestParams>::random(&mut OsRng);
        let coeffs = (0..4).map(|_| Scalar::random(&mut OsRng)).collect::<Vec<_>>();

        let actual = evaluate_polynomial(&coeffs, &x);
        let expected = coeffs[0] + coeffs[1] * x + coeffs[2] * x * x + coeffs[3] * x * x * x;

        assert_eq!(actual, expected);
    }

    #[test]
    fn split_and_join() {
        let threshold = 3;
        let num_shares = 5;
        let secret = Secret::init_with(|| Scalar::<TestParams>::random(&mut OsRng));
        let points = shamir_evaluation_points(num_shares);
        let mut shares = shamir_split(&mut OsRng, secret.clone(), threshold, &points);

        shares.remove(&points[0]);
        shares.remove(&points[3]);

        let recovered_secret = shamir_join_scalars(shares);
        assert_eq!(recovered_secret.expose_secret(), secret.expose_secret());
    }
}
