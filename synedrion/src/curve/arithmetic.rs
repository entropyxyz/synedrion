use alloc::{format, string::String, vec, vec::Vec};
use core::ops::{Add, Mul, Neg, Sub};
use crypto_bigint::ConstantTimeSelect;
use tiny_curve::TinyCurve64;

use digest::Digest;
use ecdsa::{SigningKey, VerifyingKey};
use primeorder::elliptic_curve::{
    bigint::Encoding,
    generic_array::{typenum::marker_traits::Unsigned, GenericArray},
    group::{Curve as _, GroupEncoding},
    ops::Reduce,
    point::AffineCoordinates,
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

impl HashableType for TinyCurve64 {
    fn chain_type<C: Chain>(digest: C) -> C {
        let mut digest = digest;
        // TODO(dp): pretty sure this is wrong and that this should be simpler. I think `impl<T: elliptic_curve::Curve> HashableType for T` should work.
        digest = digest.chain(&Self::ORDER.to_le_bytes());

        // TODO(dp): ProjectivePoint is not Serialize, so it's not Hashable either and I can't impl it because foreign types. Is it ok to just use the bytes here?
        let generator_bytes = <TinyCurve64 as CurveArithmetic>::ProjectivePoint::generator().to_bytes();
        digest.chain::<&[u8]>(&generator_bytes.as_ref())
    }
}

impl HashableType for k256::Secp256k1 {
    fn chain_type<C: Chain>(digest: C) -> C {
        let mut digest = digest;

        // TODO: `k256 0.14` depends on `crypto-bigint` that supports `Serialize` for `Uint`'s,
        // so we can just chain `ORDER`. For now we have to do it manually.
        // Note that since only `to_words` is available, we need to chain it
        // so that the result is the same on 32- and 64-bit targets - that is, in low-endian order.
        let words = Self::ORDER.to_words();
        for word in words {
            digest = digest.chain(&word.to_le_bytes());
        }
        // TODO(dp): ProjectivePoint is not Serialize, so it's not Hashable either and I can't impl it because foreign types. Is it ok to just use the bytes here?
        #[allow(deprecated)]
        let generator_bytes: [u8; 33] = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::generator()
            .to_bytes()
            // TODO(dp): it's unclear to me why `Into` works here but not for `TinyCurve64`
            .into();
        digest.chain(&generator_bytes.as_ref())
    }
}

pub type ScalarSh<P: SchemeParams> = <P::Curve as CurveArithmetic>::Scalar;
pub(crate) type CompressedPointSize<P: SchemeParams> = <FieldBytesSize<P::Curve> as ModulusSize>::CompressedPointSize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, PartialOrd, Ord, Zeroize)]
pub(crate) struct Scalar<P: SchemeParams>(ScalarSh<P>);

impl<P: SchemeParams> Scalar<P> {
    pub const ZERO: Self = Self(ScalarSh::<P>::ZERO);
    pub const ONE: Self = Self(ScalarSh::<P>::ONE);

    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(ScalarPrimitive::<P::Curve>::random(rng).into())
    }

    pub fn random_nonzero(rng: &mut impl CryptoRngCore) -> Self {
        Self(*NonZeroScalar::<P::Curve>::random(rng).as_ref())
    }

    pub fn mul_by_generator(&self) -> Point<P> {
        // Point::GENERATOR * self
        Point::generator() * self
    }

    /// Invert the [`Scalar`]. Returns [`None`] if the scalar is zero.
    pub fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }

    pub fn from_digest(d: impl Digest<OutputSize = FieldBytesSize<P::Curve>>) -> Self {
        // There's currently no way to make the required digest output size
        // depend on the target scalar size, so we are hardcoding it to 256 bit
        // (that is, equal to the scalar size).
        // Self(<BackendScalar as Reduce<U256>>::reduce_bytes(&d.finalize()))

        // TODO(dp): this should be much less messy. CurveArithmetic::Scalar is Reduce<Self::Uint>
        Self(<ScalarSh<P> as Reduce<<P::Curve as Curve>::Uint>>::reduce_bytes(
            &d.finalize(),
        ))
    }

    /// Convert a 32-byte hash digest into a scalar as per SEC1:
    /// <https://www.secg.org/sec1-v2.pdf< Section 4.1.3 steps 5-6 page 45
    ///
    /// SEC1 specifies to subtract the secp256k1 modulus when the byte array
    /// is larger than the modulus.

    // TODO(dp): Have to rework this (both code and docs), can't assume 32 bytes.
    // pub fn from_reduced_bytes(bytes: &[u8; 32]) -> Self {
    pub fn from_reduced_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(<ScalarSh<P> as Reduce<<P::Curve as Curve>::Uint>>::reduce_bytes(
            bytes.as_ref().into(),
        ))
    }

    /// Returns the SEC1 encoding of this scalar (big endian order).
    pub fn to_be_bytes(self) -> FieldBytes<P::Curve> {
        self.0.into()
    }

    pub fn repr_len() -> usize {
        <FieldBytesSize<P::Curve> as Unsigned>::to_usize()
    }

    pub(crate) fn to_backend(self) -> ScalarSh<P> {
        self.0
    }

    pub fn from_signing_key(sk: &SigningKey<P::Curve>) -> Secret<Self> {
        Secret::init_with(|| Self(*sk.as_nonzero_scalar().as_ref()))
    }

    /// Attempts to instantiate a `Scalar` from a slice of bytes. Assumes big-endian order.
    pub(crate) fn try_from_be_bytes(bytes: &[u8]) -> Result<Self, String> {
        let arr = GenericArray::<u8, FieldBytesSize<P::Curve>>::from_exact_iter(bytes.iter().cloned())
            .ok_or("Invalid length of a curve scalar")?;

        ScalarSh::<P>::from_repr_vartime(arr)
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

// TODO(dp): ConditionallySelectable requires Copy, which I don't think we want to impose so need to switch to ConstantTimeSelect instead.
impl<P> ConstantTimeSelect for Scalar<P>
where
    P: SchemeParams,
{
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<P::Curve as CurveArithmetic>::Scalar::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

// TODO(dp): See above
// impl<P> ConditionallySelectable for Scalar<P>
// where
//     P: SchemeParams,
// {
//     fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
//         Self(BackendScalar::conditional_select(&a.0, &b.0, choice))
//     }
// }

impl<P> Serialize for Scalar<P>
where
    P: SchemeParams,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SliceLike::<Hex>::serialize(&self.clone().to_be_bytes(), serializer)
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

pub type PointSh<P: SchemeParams> = <P::Curve as CurveArithmetic>::ProjectivePoint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Point<P: SchemeParams>(PointSh<P>);

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
        Scalar(<ScalarSh<P> as Reduce<<P::Curve as Curve>::Uint>>::reduce_bytes(&bytes))
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

    // TODO(dp): this used to take `self` which caused issues with the `Serialize for Point` impl below. Given it clones anyway, it seems like taking a ref should work as well.
    pub(crate) fn to_compressed_array(&self) -> GenericArray<u8, CompressedPointSize<P>> {
        GenericArray::<u8, CompressedPointSize<P>>::from_exact_iter(
            self.0.to_affine().to_encoded_point(true).as_bytes().iter().cloned(),
        ).expect("An AffinePoint is composed of elements of the correct size and their slice repr fits in the `CompressedPointSize`-sized array.")
    }

    pub(crate) fn to_backend(self) -> PointSh<P> {
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
        Self(ScalarSh::<P>::from(val))
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

    fn mul(self, rhs: &Scalar<P>) -> Self {
        Self(self.0.mul(&(rhs.0)))
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
    use crate::TestParams;

    use super::Scalar;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    #[test]
    fn to_and_from_bytes() {
        let mut rng = ChaChaRng::from_seed([7u8; 32]);
        let s = Scalar::<TestParams>::random(&mut rng);

        // Round trip works
        let bytes = s.to_be_bytes();
        let s_from_bytes = Scalar::try_from_be_bytes(bytes.as_ref()).expect("bytes are valid");
        assert_eq!(s, s_from_bytes);

        // …but building a `Scalar` from LE bytes does not.
        let mut bytes = bytes;
        let le_bytes = bytes
            .chunks_exact_mut(8)
            .flat_map(|word_bytes| {
                word_bytes.reverse();
                word_bytes.to_vec()
            })
            .collect::<Vec<u8>>();

        let s_from_le_bytes = Scalar::try_from_be_bytes(&le_bytes).expect("bytes are valid-ish");
        assert_ne!(s, s_from_le_bytes, "Using LE bytes should not work")
    }
}
