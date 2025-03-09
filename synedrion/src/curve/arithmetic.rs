use alloc::{format, string::String, vec, vec::Vec};
use core::ops::{Add, Mul, Neg, Rem, Sub};

use digest::XofReader;
use ecdsa::{SigningKey, VerifyingKey};
use elliptic_curve::{
    bigint::{ArrayEncoding, Concat, NonZero, Split, Zero},
    generic_array::{typenum::marker_traits::Unsigned, GenericArray},
    group::Curve as _,
    ops::Reduce,
    point::AffineCoordinates,
    scalar::FromUintUnchecked,
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, CtOption},
    Curve, CurveArithmetic, Field, FieldBytes, FieldBytesSize, Group, NonZeroScalar, PrimeField, ScalarPrimitive,
    SecretKey,
};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_encoded_bytes::{Hex, SliceLike};
use zeroize::Zeroize;

use crate::{
    tools::{
        hashing::{Chain, HashableType},
        Secret,
    },
    SchemeParams,
};

impl<C> HashableType for C
where
    C: Curve + CurveArithmetic,
    <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    fn chain_type<D: Chain>(digest: D) -> D {
        let mut digest = digest;

        // TODO: `k256 0.14` depends on `crypto-bigint` that supports `Serialize` for `Uint`'s,
        // so we can just chain `ORDER`. For now we have to do it manually.
        // Note that since only `as_ref` (yielding `&[Limb]`) is available, we need to chain it
        // so that the result is the same on 32- and 64-bit targets - that is, in low-endian order.
        let order = Self::ORDER;
        let limbs = order.as_ref();
        for limb in limbs {
            digest = digest.chain(&limb.0.to_le_bytes());
        }

        // TODO: in `k256` the `generator()` method is deprecated in favor of `GENERATOR` but that is not exported for other curves.
        #[allow(deprecated)]
        let generator_bytes = <Self as CurveArithmetic>::ProjectivePoint::generator()
            .to_affine()
            .to_encoded_point(true);
        digest.chain::<&[u8]>(&generator_bytes.as_bytes())
    }
}

type BackendScalar<P> = <<P as SchemeParams>::Curve as CurveArithmetic>::Scalar;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, PartialOrd, Ord, Zeroize)]
pub(crate) struct Scalar<P: SchemeParams>(BackendScalar<P>);

impl<P: SchemeParams> Scalar<P> {
    pub const ZERO: Self = Self(BackendScalar::<P>::ZERO);
    pub const ONE: Self = Self(BackendScalar::<P>::ONE);

    pub fn new(backend_scalar: BackendScalar<P>) -> Self {
        Self(backend_scalar)
    }

    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(ScalarPrimitive::<P::Curve>::random(rng).into())
    }

    pub fn random_nonzero(rng: &mut impl CryptoRngCore) -> Self {
        Self(*NonZeroScalar::<P::Curve>::random(rng).as_ref())
    }

    pub fn mul_by_generator(&self) -> Point<P> {
        Point::generator() * self
    }

    /// Invert the [`Scalar`]. Returns [`None`] if the scalar is zero.
    pub fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }

    /// Read twice the number of bytes in a curve [`Scalar`] from the [`XofReader`], then reduce
    /// modulo the curve order to ensure a valid, unbiased scalar.
    pub fn from_xof_reader(reader: &mut impl XofReader) -> Self {
        let bytes_lo = reader.read_boxed(Self::repr_len());
        let bytes_lo = GenericArray::<_, <<P::Curve as Curve>::Uint as ArrayEncoding>::ByteSize>::from_slice(&bytes_lo);
        let uint_lo = <P::Curve as Curve>::Uint::from_be_byte_array(bytes_lo.clone());

        let bytes_hi = reader.read_boxed(Self::repr_len());
        let bytes_hi = GenericArray::<_, <<P::Curve as Curve>::Uint as ArrayEncoding>::ByteSize>::from_slice(&bytes_hi);
        let uint_hi = <P::Curve as Curve>::Uint::from_be_byte_array(bytes_hi.clone());

        // TODO: Invert the order when the elliptic curve stack upgrades (bigint v0.5 used hi/lo, but v0.6 switches to lo/hi)
        let wide_uint = uint_hi.concat(&uint_lo);
        // TODO: When the elliptic curve stack upgrades to crypto-bigint v0.6 we can use RemMixed and
        // avoid casting the ORDER to a wide.
        let wide_order =
            NonZero::new(<P::Curve as Curve>::Uint::ZERO.concat(&P::Curve::ORDER)).expect("ORDER is non-zero");
        let wide_reduced = wide_uint.rem(wide_order);
        let (_, reduced) = wide_reduced.split();
        debug_assert!(reduced < P::Curve::ORDER && reduced != <P::Curve as Curve>::Uint::ZERO);
        let scalar = BackendScalar::<P>::from_uint_unchecked(reduced);
        Self(scalar)
    }

    /// Convert a 32-byte hash digest into a scalar as per SEC1:
    /// <https://www.secg.org/sec1-v2.pdf< Section 4.1.3 steps 5-6 page 45
    ///
    /// SEC1 specifies to subtract the curve modulus when the byte array
    /// is larger than the modulus.
    pub fn from_reduced_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(<<P::Curve as CurveArithmetic>::Scalar as Reduce<
            <P::Curve as Curve>::Uint,
        >>::reduce_bytes(bytes.as_ref().into()))
    }

    /// Returns the SEC1 encoding of this scalar (big endian order).
    pub fn to_be_bytes(self) -> FieldBytes<P::Curve> {
        self.0.into()
    }

    pub fn repr_len() -> usize {
        <FieldBytesSize<P::Curve> as Unsigned>::to_usize()
    }

    pub(crate) fn to_backend(self) -> BackendScalar<P> {
        self.0
    }

    /// Attempts to instantiate a `Scalar` from a slice of bytes. Assumes big-endian order.
    pub(crate) fn try_from_be_bytes(bytes: &[u8]) -> Result<Self, String> {
        let arr = GenericArray::<u8, FieldBytesSize<P::Curve>>::from_exact_iter(bytes.iter().cloned())
            .ok_or("Invalid length of a curve scalar")?;

        BackendScalar::<P>::from_repr_vartime(arr)
            .map(Self)
            .ok_or_else(|| "Invalid curve scalar representation".into())
    }
}

impl<P: SchemeParams> Secret<Scalar<P>> {
    pub fn to_signing_key(&self) -> Option<SigningKey<P::Curve>> {
        let nonzero_scalar: Secret<NonZeroScalar<_>> =
            Secret::maybe_init_with(|| Option::from(NonZeroScalar::new(self.expose_secret().0)))?;
        // SigningKey can be instantiated from NonZeroScalar directly, but that method takes it by value,
        // so it is more likely to leave traces of secret data on the stack. `SecretKey::from()` takes a reference.
        let secret_key = SecretKey::from(nonzero_scalar.expose_secret());
        Some(SigningKey::from(&secret_key))
    }
}

pub(crate) fn secret_split<P: SchemeParams>(
    rng: &mut impl CryptoRngCore,
    scalar: Secret<Scalar<P>>,
    num: usize,
) -> Vec<Secret<Scalar<P>>> {
    if num == 1 {
        return vec![scalar];
    }

    let mut parts = (0..(num - 1))
        .map(|_| Secret::init_with(|| Scalar::random_nonzero(rng)))
        .collect::<Vec<_>>();
    let partial_sum: Secret<Scalar<P>> = parts.iter().cloned().sum();
    parts.push(scalar - partial_sum);
    parts
}

impl<'a, P> TryFrom<&'a [u8]> for Scalar<P>
where
    P: SchemeParams,
{
    type Error = String;
    fn try_from(val: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_be_bytes(val)
    }
}

impl<P> From<&NonZeroScalar<P::Curve>> for Scalar<P>
where
    P: SchemeParams,
{
    fn from(val: &NonZeroScalar<P::Curve>) -> Self {
        Self(*val.as_ref())
    }
}

impl<P> ConditionallySelectable for Scalar<P>
where
    P: SchemeParams,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<P::Curve as CurveArithmetic>::Scalar::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl<P> Serialize for Scalar<P>
where
    P: SchemeParams,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SliceLike::<Hex>::serialize(&self.to_be_bytes(), serializer)
    }
}

impl<'de, P> Deserialize<'de> for Scalar<P>
where
    P: SchemeParams,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SliceLike::<Hex>::deserialize(deserializer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Point<P: SchemeParams>(<P::Curve as CurveArithmetic>::ProjectivePoint);

impl<P> Point<P>
where
    P: SchemeParams,
{
    pub fn generator() -> Self {
        Self(<<P::Curve as CurveArithmetic>::ProjectivePoint as Group>::generator())
    }
    pub fn identity() -> Self {
        Self(<<P::Curve as CurveArithmetic>::ProjectivePoint as Group>::identity())
    }

    pub fn x_coordinate(&self) -> Scalar<P> {
        let bytes = self.0.to_affine().x();
        Scalar(<BackendScalar<P> as Reduce<<P::Curve as Curve>::Uint>>::reduce_bytes(
            &bytes,
        ))
    }

    pub fn from_verifying_key(key: &VerifyingKey<P::Curve>) -> Self {
        Self((*key.as_affine()).into())
    }

    /// Convert a [`Point`] to a [`VerifyingKey`] wrapped in an [`Option`]. Returns [`None`] if the
    /// `Point` is the point at infinity.
    pub fn to_verifying_key(self) -> Option<VerifyingKey<P::Curve>> {
        VerifyingKey::from_affine(self.0.to_affine()).ok()
    }

    pub(crate) fn try_from_compressed_bytes(bytes: &[u8]) -> Result<Self, String> {
        let ep = EncodedPoint::<P::Curve>::from_bytes(bytes).map_err(|err| format!("{err}"))?;

        // Unwrap CtOption into Option
        let cp_opt: Option<_> = <<P::Curve as CurveArithmetic>::ProjectivePoint>::from_encoded_point(&ep).into();
        cp_opt
            .map(Self)
            .ok_or_else(|| "Invalid curve point representation".into())
    }

    pub(crate) fn to_compressed_array(
        self,
    ) -> GenericArray<u8, <FieldBytesSize<P::Curve> as ModulusSize>::CompressedPointSize> {
        GenericArray::from_exact_iter(
            self.0.to_affine().to_encoded_point(true).as_bytes().iter().cloned(),
        ).expect("An AffinePoint is composed of elements of the correct size and their slice repr fits in the `CompressedPointSize`-sized array.")
    }

    pub(crate) fn to_backend(self) -> <P::Curve as CurveArithmetic>::ProjectivePoint {
        self.0
    }
}

impl<'a, P> TryFrom<&'a [u8]> for Point<P>
where
    P: SchemeParams,
{
    type Error = String;
    fn try_from(val: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_compressed_bytes(val)
    }
}

impl<P> Serialize for Point<P>
where
    P: SchemeParams,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SliceLike::<Hex>::serialize(&self.to_compressed_array(), serializer)
    }
}

impl<'de, P> Deserialize<'de> for Point<P>
where
    P: SchemeParams,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SliceLike::<Hex>::deserialize(deserializer)
    }
}

impl<P> From<u64> for Scalar<P>
where
    P: SchemeParams,
{
    fn from(val: u64) -> Self {
        Self(BackendScalar::<P>::from(val))
    }
}

impl<P> Neg for Scalar<P>
where
    P: SchemeParams,
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl<P> Add<Scalar<P>> for Scalar<P>
where
    P: SchemeParams,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Scalar(self.0.add(&rhs.0))
    }
}

impl<P> Add<&Scalar<P>> for &Scalar<P>
where
    P: SchemeParams,
{
    type Output = Scalar<P>;

    fn add(self, rhs: &Scalar<P>) -> Scalar<P> {
        Scalar(self.0.add(&rhs.0))
    }
}

impl<P> Add<&Scalar<P>> for Scalar<P>
where
    P: SchemeParams,
{
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self(self.0.add(&rhs.0))
    }
}

impl<P> Add<Point<P>> for Point<P>
where
    P: SchemeParams,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.add(&(rhs.0)))
    }
}

impl<P> Sub<Scalar<P>> for Scalar<P>
where
    P: SchemeParams,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0.sub(&(rhs.0)))
    }
}

impl<P> Sub<&Scalar<P>> for Scalar<P>
where
    P: SchemeParams,
{
    type Output = Self;

    fn sub(self, rhs: &Scalar<P>) -> Self {
        Self(self.0.sub(&(rhs.0)))
    }
}

impl<P> Mul<Scalar<P>> for Point<P>
where
    P: SchemeParams,
{
    type Output = Self;

    fn mul(self, rhs: Scalar<P>) -> Self {
        Self(self.0.mul(&(rhs.0)))
    }
}

impl<P> Mul<&Scalar<P>> for Point<P>
where
    P: SchemeParams,
{
    type Output = Self;

    fn mul(self, rhs: &Scalar<P>) -> Self {
        Self(self.0.mul(&(rhs.0)))
    }
}

impl<P> Mul<&Scalar<P>> for &Point<P>
where
    P: SchemeParams,
{
    type Output = Point<P>;

    fn mul(self, rhs: &Scalar<P>) -> Point<P> {
        Point(self.0.mul(&(rhs.0)))
    }
}

impl<P> Mul<Scalar<P>> for Scalar<P>
where
    P: SchemeParams,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self(self.0.mul(&(rhs.0)))
    }
}

impl<P> Mul<&Scalar<P>> for Scalar<P>
where
    P: SchemeParams,
{
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self {
        Self(self.0.mul(&(rhs.0)))
    }
}

impl<P> Mul<Scalar<P>> for &Point<P>
where
    P: SchemeParams,
{
    type Output = Point<P>;

    fn mul(self, rhs: Scalar<P>) -> Self::Output {
        Point(self.0.mul(&(rhs.0)))
    }
}

impl<P> core::iter::Sum for Scalar<P>
where
    P: SchemeParams,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Self::ZERO)
    }
}

impl<'a, P> core::iter::Sum<&'a Self> for Scalar<P>
where
    P: SchemeParams,
{
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl<P> core::iter::Product for Scalar<P>
where
    P: SchemeParams,
{
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Mul::mul).unwrap_or(Self::ONE)
    }
}

impl<P> core::iter::Sum for Point<P>
where
    P: SchemeParams,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Self::identity())
    }
}

impl<'a, P> core::iter::Sum<&'a Self> for Point<P>
where
    P: SchemeParams,
{
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

#[cfg(test)]
mod test {
    use crate::{SchemeParams, TestParams};

    use super::Scalar;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test_log::test]
    fn to_and_from_bytes() {
        let mut rng = ChaChaRng::from_seed([7u8; 32]);
        let s = Scalar::<TestParams>::random(&mut rng);

        // Round trip works
        let be_bytes = s.to_be_bytes();
        let s_from_be_bytes = Scalar::try_from_be_bytes(be_bytes.as_ref()).expect("bytes are valid");
        assert_eq!(s, s_from_be_bytes);

        let chunk_size = TestParams::SECURITY_PARAMETER / 8;
        // …but building a `Scalar` from LE bytes does not.
        let mut bytes = be_bytes;
        let le_bytes = bytes
            .chunks_exact_mut(chunk_size)
            .flat_map(|word_bytes| {
                word_bytes.reverse();
                word_bytes.to_vec()
            })
            .collect::<Vec<u8>>();

        let s_from_le_bytes = Scalar::try_from_be_bytes(&le_bytes).expect("bytes are valid-ish");
        assert_ne!(s, s_from_le_bytes, "Using LE bytes should not work")
    }
}
