use alloc::collections::BTreeMap;
use alloc::vec::Vec;

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
    // TODO (#87): it should be still secure, right?
    // Potentially we can derive them from Session ID.
    (1..=u32::try_from(num_shares).expect("The number of shares cannot be over 2^32-1"))
        .map(|idx| ShareIdx(Scalar::from(idx)))
        .collect()
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
        let mut res = self.0[0];
        let mut xp = x.0;
        for coeff in self.0[1..].iter() {
            res = res + coeff * &xp;
            xp = xp * x.0;
        }
        res
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

pub(crate) fn interpolation_coeff(idxs: &[ShareIdx], exclude_idx: usize) -> Scalar {
    // TODO: the inversions can be precalculated if we calculate multiple interpolation coeffs
    // for the same set of shares.
    idxs.iter()
        .enumerate()
        .filter(|(i, _)| i != &exclude_idx)
        .map(|(_, idx)| idx.0 * (idx.0 - idxs[exclude_idx].0).invert().unwrap())
        .product()
}

#[cfg(test)]
pub(crate) fn shamir_join_scalars<'a>(
    pairs: impl Iterator<Item = (&'a ShareIdx, &'a Scalar)>,
) -> Scalar {
    let (share_idxs, values): (Vec<_>, Vec<_>) = pairs.map(|(k, v)| (*k, *v)).unzip();
    values
        .iter()
        .enumerate()
        .map(|(i, val)| val * &interpolation_coeff(&share_idxs, i))
        .sum()
}

pub(crate) fn shamir_join_points<'a>(
    pairs: impl Iterator<Item = (&'a ShareIdx, &'a Point)>,
) -> Point {
    let (share_idxs, values): (Vec<_>, Vec<_>) = pairs.map(|(k, v)| (*k, *v)).unzip();
    values
        .iter()
        .enumerate()
        .map(|(i, val)| val * &interpolation_coeff(&share_idxs, i))
        .sum()
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{shamir_evaluation_points, shamir_join_scalars, shamir_split};
    use crate::curve::Scalar;

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
