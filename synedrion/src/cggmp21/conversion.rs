use crypto_bigint::{BitOps, Encoding, Zero};

use super::params::SchemeParams;
use crate::{
    curve::{Scalar, ORDER},
    paillier::PaillierParams,
    tools::Secret,
    uint::{PublicSigned, SecretSigned},
};

fn uint_from_scalar<P: SchemeParams>(value: &Scalar) -> <P::Paillier as PaillierParams>::Uint {
    let scalar_bytes = value.to_be_bytes();
    let mut repr = <P::Paillier as PaillierParams>::Uint::zero().to_be_bytes();

    let uint_len = repr.as_ref().len();
    let scalar_len = scalar_bytes.len();

    repr.as_mut()
        .get_mut(uint_len - scalar_len..)
        .expect("PaillierParams::Uint is expected to be bigger than a Scalar")
        .copy_from_slice(&scalar_bytes);
    <P::Paillier as PaillierParams>::Uint::from_be_bytes(repr)
}

/// Converts a [`Scalar`] to a [`PublicSigned`].
///
/// Assumes using a curve whose order is at most the width of `Uint` minus 1 bit.
pub(crate) fn public_signed_from_scalar<P: SchemeParams>(
    value: &Scalar,
) -> PublicSigned<<P::Paillier as PaillierParams>::Uint> {
    PublicSigned::new_positive(uint_from_scalar::<P>(value), ORDER.bits_vartime() as u32).expect(concat![
        "a curve scalar value is smaller than the half of `PaillierParams::Uint` range, ",
        "so it is still positive when treated as a 2-complement signed value"
    ])
}

/// Converts an integer to the associated curve scalar type.
pub(crate) fn scalar_from_uint<P: SchemeParams>(value: &<P::Paillier as PaillierParams>::Uint) -> Scalar {
    let r = *value % P::CURVE_ORDER;

    let repr = r.to_be_bytes();
    let uint_len = repr.as_ref().len();
    let scalar_len = Scalar::repr_len();

    // Can unwrap here since the value is within the Scalar range
    Scalar::try_from_be_bytes(
        repr.as_ref()
            .get(uint_len - scalar_len..)
            .expect("Uint is assumed to be bigger than Scalar"),
    )
    .expect("the value was reduced modulo curve order, so it's a valid curve scalar")
}

/// Converts a `PublicSigned`-wrapped integer to the associated curve scalar type.
pub(crate) fn scalar_from_signed<P: SchemeParams>(
    value: &PublicSigned<<P::Paillier as PaillierParams>::Uint>,
) -> Scalar {
    let abs_value = scalar_from_uint::<P>(&value.abs());
    if value.is_negative() {
        -abs_value
    } else {
        abs_value
    }
}

/// Converts a secret-wrapped uint to a secret-wrapped [`Scalar`], reducing the value modulo curve order.
fn secret_scalar_from_uint<P: SchemeParams>(value: &Secret<<P::Paillier as PaillierParams>::Uint>) -> Secret<Scalar> {
    let r = value % &P::CURVE_ORDER;

    let repr = Secret::init_with(|| r.expose_secret().to_be_bytes());
    let uint_len = repr.expose_secret().as_ref().len();
    let scalar_len = Scalar::repr_len();

    // Can unwrap here since the value is within the Scalar range
    Secret::init_with(|| {
        Scalar::try_from_be_bytes(
            repr.expose_secret()
                .as_ref()
                .get(uint_len - scalar_len..)
                .expect("Uint is assumed to be bigger than Scalar"),
        )
        .expect("the value was reduced modulo `CURVE_ORDER`, so it's a valid curve scalar")
    })
}

fn secret_uint_from_scalar<P: SchemeParams>(value: &Secret<Scalar>) -> Secret<<P::Paillier as PaillierParams>::Uint> {
    let scalar_bytes = Secret::init_with(|| value.expose_secret().to_be_bytes());
    let mut repr = Secret::init_with(|| <P::Paillier as PaillierParams>::Uint::zero().to_be_bytes());

    let uint_len = repr.expose_secret().as_ref().len();
    let scalar_len = scalar_bytes.expose_secret().len();

    debug_assert!(uint_len >= scalar_len);
    repr.expose_secret_mut()
        .as_mut()
        .get_mut(uint_len - scalar_len..)
        .expect("<P::Paillier as PaillierParams>::Uint is assumed to be configured to be bigger than Scalar")
        .copy_from_slice(scalar_bytes.expose_secret());
    Secret::init_with(|| <P::Paillier as PaillierParams>::Uint::from_be_bytes(*repr.expose_secret()))
}

/// Converts a secret-wrapped [`Scalar`] to a [`SecretSigned`].
///
/// Assumes using a curve whose order is at most the width of `Uint` minus 1 bit.
pub(crate) fn secret_signed_from_scalar<P: SchemeParams>(
    value: &Secret<Scalar>,
) -> SecretSigned<<P::Paillier as PaillierParams>::Uint> {
    SecretSigned::new_modulo(
        secret_uint_from_scalar::<P>(value),
        &P::CURVE_ORDER,
        P::CURVE_ORDER.as_ref().bits_vartime(),
    )
    .expect(concat![
        "a curve scalar value is smaller than the curve order, ",
        "and the curve order fits in `PaillierParams::Uint`"
    ])
}

/// Converts a [`SecretSigned`] to a secret-wrapped [`Scalar`].
pub(crate) fn secret_scalar_from_signed<P: SchemeParams>(
    value: &SecretSigned<<P::Paillier as PaillierParams>::Uint>,
) -> Secret<Scalar> {
    let abs_value = secret_scalar_from_uint::<P>(&value.abs_value());
    Secret::<Scalar>::conditional_select(&abs_value, &-&abs_value, value.is_negative())
}
