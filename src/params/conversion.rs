use crypto_bigint::{BitOps, NonZero, Zero};
use elliptic_curve::{bigint::Encoding, Curve, CurveArithmetic, PrimeField};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

use super::traits::SchemeParams;
use crate::{
    curve::Scalar,
    paillier::PaillierParams,
    tools::Secret,
    uint::{BoxedEncoding, Extendable, PublicSigned, SecretSigned},
};

fn curve_order<P: SchemeParams>() -> <P::Paillier as PaillierParams>::Uint {
    // The current version of `elliptic_curve` uses `crypto-bigint` 0.5,
    // and our Paillier code uses 0.6. This function converts the integer between the two.
    let order_repr = P::Curve::ORDER.to_be_bytes();
    let mut uint_repr = <P::Paillier as PaillierParams>::Uint::zero().to_be_bytes();
    let uint_repr_len = uint_repr.len();
    uint_repr
        .get_mut(uint_repr_len - order_repr.as_ref().len()..)
        .expect("the curve order fits into `Uint`")
        .copy_from_slice(order_repr.as_ref());
    <P::Paillier as PaillierParams>::Uint::try_from_be_bytes(&uint_repr).expect("the representation size is correct")
}

fn curve_order_uint<P: SchemeParams>() -> NonZero<<P::Paillier as PaillierParams>::Uint> {
    NonZero::new(curve_order::<P>()).expect("the curve order is non-zero")
}

fn curve_order_wide_uint<P: SchemeParams>() -> NonZero<<P::Paillier as PaillierParams>::WideUint> {
    NonZero::new(curve_order::<P>().to_wide()).expect("the curve order is non-zero")
}

fn uint_from_scalar<P: SchemeParams>(value: &Scalar<P>) -> <P::Paillier as PaillierParams>::Uint {
    let scalar_bytes = value.to_be_bytes();
    let mut repr = <P::Paillier as PaillierParams>::Uint::zero().to_be_bytes();

    let uint_len = repr.as_ref().len();
    let scalar_len = scalar_bytes.len();

    repr.as_mut()
        .get_mut(uint_len - scalar_len..)
        .expect("PaillierParams::Uint is expected to be bigger than a Scalar")
        .copy_from_slice(&scalar_bytes);
    <P::Paillier as PaillierParams>::Uint::try_from_be_bytes(&repr).expect("`repr` has the correct length")
}

/// Converts a [`Scalar`] to a [`PublicSigned`].
///
/// Assumes using a curve whose order is at most the width of `Uint` minus 1 bit.
pub(crate) fn public_signed_from_scalar<P: SchemeParams>(
    value: &Scalar<P>,
) -> PublicSigned<<P::Paillier as PaillierParams>::Uint> {
    let order_bits = curve_order_uint::<P>().bits_vartime();
    PublicSigned::new_positive(uint_from_scalar::<P>(value), order_bits).expect(concat![
        "a curve scalar value is smaller than the half of `PaillierParams::Uint` range, ",
        "so it is still positive when treated as a 2-complement signed value"
    ])
}

/// Converts an integer to the associated curve scalar type.
pub(crate) fn scalar_from_wide_uint<P: SchemeParams>(value: &<P::Paillier as PaillierParams>::WideUint) -> Scalar<P> {
    let r = *value % curve_order_wide_uint::<P>();

    let repr = r.to_be_bytes();
    let uint_len = repr.as_ref().len();
    let scalar_len = Scalar::<P>::repr_len();

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
) -> Scalar<P> {
    let abs_value = scalar_from_wide_uint::<P>(&value.abs().to_wide());
    if value.is_negative() {
        -abs_value
    } else {
        abs_value
    }
}

pub(crate) fn scalar_from_wide_signed<P: SchemeParams>(
    value: &PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
) -> Scalar<P> {
    let abs_value = scalar_from_wide_uint::<P>(&value.abs());
    if value.is_negative() {
        -abs_value
    } else {
        abs_value
    }
}

/// Converts a secret-wrapped uint to a secret-wrapped [`Scalar`], reducing the value modulo curve order.
fn secret_scalar_from_wide_uint<P: SchemeParams>(
    value: &Secret<<P::Paillier as PaillierParams>::WideUint>,
) -> Secret<Scalar<P>> {
    let r = value % &curve_order_wide_uint::<P>();

    let repr = SecretBox::<[u8]>::from(r.expose_secret().to_be_bytes());
    let uint_len = repr.expose_secret().as_ref().len();
    let scalar_len = Scalar::<P>::repr_len();

    // Can unwrap here since the value is within the Scalar range
    Secret::init_with(|| {
        Scalar::try_from_be_bytes(
            repr.expose_secret()
                .as_ref()
                .get(uint_len - scalar_len..)
                .expect("Uint is assumed to be bigger than Scalar"),
        )
        .expect("the value was reduced modulo curve order, so it's a valid curve scalar")
    })
}

fn secret_uint_from_scalar<P: SchemeParams>(
    value: &Secret<Scalar<P>>,
) -> Secret<<P::Paillier as PaillierParams>::Uint> {
    let scalar_bytes = SecretBox::<[u8]>::from(value.expose_secret().to_be_bytes());
    let mut repr = SecretBox::<[u8]>::from(<P::Paillier as PaillierParams>::Uint::zero().to_be_bytes());

    let uint_len = repr.expose_secret().as_ref().len();
    let scalar_len = scalar_bytes.expose_secret().len();

    debug_assert!(uint_len >= scalar_len);
    repr.expose_secret_mut()
        .as_mut()
        .get_mut(uint_len - scalar_len..)
        .expect("<P::Paillier as PaillierParams>::Uint is assumed to be configured to be bigger than Scalar")
        .copy_from_slice(scalar_bytes.expose_secret());
    Secret::try_init_with(|| <P::Paillier as PaillierParams>::Uint::try_from_be_bytes(repr.expose_secret()))
        .expect("`repr` has the correct length")
}

/// Converts a secret-wrapped [`Scalar`] to a [`SecretSigned`].
///
/// Assumes using a curve whose order is at most the width of `Uint` minus 1 bit.
pub(crate) fn secret_signed_from_scalar<P: SchemeParams>(
    value: &Secret<Scalar<P>>,
) -> SecretSigned<<P::Paillier as PaillierParams>::Uint> {
    SecretSigned::new_modulo(
        secret_uint_from_scalar::<P>(value),
        &curve_order_uint::<P>(),
        <<P::Curve as CurveArithmetic>::Scalar as PrimeField>::NUM_BITS,
    )
    .expect(concat![
        "a curve scalar value is smaller than the curve order, ",
        "and the curve order fits in `PaillierParams::Uint`"
    ])
}

/// Converts a [`SecretSigned`] to a secret-wrapped [`Scalar`].
pub(crate) fn secret_scalar_from_signed<P: SchemeParams>(
    value: &SecretSigned<<P::Paillier as PaillierParams>::Uint>,
) -> Secret<Scalar<P>> {
    let abs_value = secret_scalar_from_wide_uint::<P>(&value.abs_value().to_wide());
    Secret::<Scalar<P>>::conditional_select(&abs_value, &-&abs_value, value.is_negative())
}

/// Converts a [`SecretSigned`] to a secret-wrapped [`Scalar`].
pub(crate) fn secret_scalar_from_wide_signed<P: SchemeParams>(
    value: &SecretSigned<<P::Paillier as PaillierParams>::WideUint>,
) -> Secret<Scalar<P>> {
    let abs_value = secret_scalar_from_wide_uint::<P>(&value.abs_value());
    Secret::<Scalar<P>>::conditional_select(&abs_value, &-&abs_value, value.is_negative())
}
