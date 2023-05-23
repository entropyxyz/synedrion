use alloc::vec::Vec;

use rand_core::CryptoRngCore;

use crate::tools::group::Scalar;

pub(crate) fn shamir_evaluation_points(num_shares: usize) -> Vec<Scalar> {
    // For now we are hardcoding the points to be 1, 2, ..., n.
    // CHECK: it should be still secure, right?
    // Potentially we can derive them from Session ID.
    (1..=num_shares).map(Scalar::from).collect()
}

pub(crate) fn shamir_split(
    rng: &mut impl CryptoRngCore,
    secret: &Scalar,
    threshold: usize,
    points: &[Scalar],
) -> Vec<Scalar> {
    let coeffs = (0..threshold - 1)
        .map(|_| Scalar::random_nonzero(rng))
        .collect::<Vec<_>>();
    points
        .iter()
        .map(|x| {
            let mut res = *secret;
            let mut xp = *x;
            for coeff in coeffs.iter() {
                res = res + coeff * &xp;
                xp = &xp * x;
            }
            res
        })
        .collect()
}

pub(crate) fn interpolation_coeff(points: &[Scalar], idx: usize) -> Scalar {
    points
        .iter()
        .enumerate()
        .filter(|(j, _)| j != &idx)
        .map(|(_, x)| x * &(x - &points[idx]).invert().unwrap())
        .product()
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{interpolation_coeff, shamir_evaluation_points, shamir_split};
    use crate::tools::group::Scalar;

    fn shamir_join(secrets: &[Scalar], points: &[Scalar]) -> Scalar {
        secrets
            .iter()
            .enumerate()
            .map(|(idx, secret)| secret * &interpolation_coeff(points, idx))
            .sum()
    }

    #[test]
    fn split_and_join() {
        let threshold = 3;
        let num_shares = 5;
        let secret = Scalar::random(&mut OsRng);
        let points = shamir_evaluation_points(num_shares);
        let shares = shamir_split(&mut OsRng, &secret, threshold, &points);

        let recovered_secret = shamir_join(
            &[shares[1], shares[2], shares[4]],
            &[points[1], points[2], points[4]],
        );
        assert_eq!(recovered_secret, secret);
    }
}
