use alloc::{format, string::String, vec, vec::Vec};
use core::{
    default::Default,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use digest::Digest;
use k256::elliptic_curve::{
    bigint::U256, // Note that this type is different from typenum::U256
    generic_array::{typenum::marker_traits::Unsigned, GenericArray},
    ops::Reduce,
    point::AffineCoordinates,
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, CtOption},
    Curve as _,
    Field,
    FieldBytesSize,
    NonZeroScalar,
    SecretKey,
};
use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::group::ff::PrimeField,
    Secp256k1,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_encoded_bytes::{Hex, SliceLike};
use zeroize::Zeroize;

use crate::tools::{
    hashing::{Chain, HashableType},
    Secret,
};

pub(crate) type Curve = Secp256k1;
pub(crate) type BackendScalar = k256::Scalar;
pub(crate) type BackendPoint = k256::ProjectivePoint;
pub(crate) type CompressedPointSize = <FieldBytesSize<Secp256k1> as ModulusSize>::CompressedPointSize;

pub(crate) const ORDER: U256 = Secp256k1::ORDER;

impl HashableType for Curve {
    fn chain_type<C: Chain>(digest: C) -> C {
        let mut digest = digest;

        // TODO: `k256 0.14` depends on `crypto-bigint` that supports `Serialize` for `Uint`'s,
        // so we can just chain `ORDER`. For now we have to do it manually.
        // Note that since only `to_words` is available, we need to chain it
        // so that the result is the same on 32- and 64-bit targets - that is, in low-endian order.
        let words = ORDER.to_words();
        for word in words {
            digest = digest.chain(&word.to_le_bytes());
        }

        digest.chain(&Point::GENERATOR)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, PartialOrd, Ord, Zeroize)]
pub(crate) struct Scalar(BackendScalar);

impl Scalar {
    pub const ZERO: Self = Self(BackendScalar::ZERO);
    pub const ONE: Self = Self(BackendScalar::ONE);

    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(BackendScalar::random(rng))
    }

    pub fn random_nonzero(rng: &mut impl CryptoRngCore) -> Self {
        Self(*NonZeroScalar::<Secp256k1>::random(rng).as_ref())
    }

    pub fn mul_by_generator(&self) -> Point {
        Point::GENERATOR * self
    }

    /// Invert the [`Scalar`]. Returns [`None`] if the scalar is zero.
    pub fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }

    pub fn from_digest(d: impl Digest<OutputSize = FieldBytesSize<Secp256k1>>) -> Self {
        // There's currently no way to make the required digest output size
        // depend on the target scalar size, so we are hardcoding it to 256 bit
        // (that is, equal to the scalar size).
        Self(<BackendScalar as Reduce<U256>>::reduce_bytes(&d.finalize()))
    }

    /// Convert a 32-byte hash digest into a scalar as per SEC1:
    /// <https://www.secg.org/sec1-v2.pdf< Section 4.1.3 steps 5-6 page 45
    ///
    /// SEC1 specifies to subtract the secp256k1 modulus when the byte array
    /// is larger than the modulus.
    pub fn from_reduced_bytes(bytes: &[u8; 32]) -> Self {
        let arr = GenericArray::<u8, FieldBytesSize<Secp256k1>>::from(*bytes);
        Self(<BackendScalar as Reduce<U256>>::reduce_bytes(&arr))
    }

    /// Returns the SEC1 encoding of this scalar (big endian order).
    pub fn to_be_bytes(self) -> k256::FieldBytes {
        self.0.to_bytes()
    }

    pub fn repr_len() -> usize {
        <FieldBytesSize<Secp256k1> as Unsigned>::to_usize()
    }

    pub(crate) fn to_backend(self) -> BackendScalar {
        self.0
    }

    pub fn from_signing_key(sk: &SigningKey) -> Secret<Self> {
        Secret::init_with(|| Self(*sk.as_nonzero_scalar().as_ref()))
    }

    /// Attempts to instantiate a `Scalar` from a slice of bytes. Assumes big-endian order.
    pub(crate) fn try_from_be_bytes(bytes: &[u8]) -> Result<Self, String> {
        let arr = GenericArray::<u8, FieldBytesSize<Secp256k1>>::from_exact_iter(bytes.iter().cloned())
            .ok_or("Invalid length of a curve scalar")?;

        BackendScalar::from_repr_vartime(arr)
            .map(Self)
            .ok_or_else(|| "Invalid curve scalar representation".into())
    }
}

impl Secret<Scalar> {
    pub fn to_signing_key(&self) -> Option<SigningKey> {
        let nonzero_scalar: Secret<NonZeroScalar<_>> =
            Secret::maybe_init_with(|| Option::from(NonZeroScalar::new(self.expose_secret().0)))?;
        // SigningKey can be instantiated from NonZeroScalar directly, but that method takes it by value,
        // so it is more likely to leave traces of secret data on the stack. `SecretKey::from()` takes a reference.
        let secret_key = SecretKey::from(nonzero_scalar.expose_secret());
        Some(SigningKey::from(&secret_key))
    }
}

pub(crate) fn secret_split(rng: &mut impl CryptoRngCore, scalar: Secret<Scalar>, num: usize) -> Vec<Secret<Scalar>> {
    if num == 1 {
        return vec![scalar];
    }

    let mut parts = (0..(num - 1))
        .map(|_| Secret::init_with(|| Scalar::random_nonzero(rng)))
        .collect::<Vec<_>>();
    let partial_sum: Secret<Scalar> = parts.iter().cloned().sum();
    parts.push(scalar - partial_sum);
    parts
}

impl<'a> TryFrom<&'a [u8]> for Scalar {
    type Error = String;
    fn try_from(val: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_be_bytes(val)
    }
}

impl From<&NonZeroScalar<Secp256k1>> for Scalar {
    fn from(val: &NonZeroScalar<Secp256k1>) -> Self {
        Self(*val.as_ref())
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(BackendScalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl Serialize for Scalar {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SliceLike::<Hex>::serialize(&self.to_be_bytes(), serializer)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SliceLike::<Hex>::deserialize(deserializer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Point(BackendPoint);

impl Point {
    pub const GENERATOR: Self = Self(BackendPoint::GENERATOR);

    pub const IDENTITY: Self = Self(BackendPoint::IDENTITY);

    pub fn x_coordinate(&self) -> Scalar {
        let bytes = self.0.to_affine().x();
        Scalar(<BackendScalar as Reduce<U256>>::reduce_bytes(&bytes))
    }

    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self(key.as_affine().into())
    }

    /// Convert a [`Point`] to a [`VerifyingKey`] wrapped in an [`Option`]. Returns [`None`] if the
    /// `Point` is the point at infinity.
    pub fn to_verifying_key(self) -> Option<VerifyingKey> {
        VerifyingKey::from_affine(self.0.to_affine()).ok()
    }

    pub(crate) fn try_from_compressed_bytes(bytes: &[u8]) -> Result<Self, String> {
        let ep = EncodedPoint::<Secp256k1>::from_bytes(bytes).map_err(|err| format!("{err}"))?;

        // Unwrap CtOption into Option
        let cp_opt: Option<BackendPoint> = BackendPoint::from_encoded_point(&ep).into();
        cp_opt
            .map(Self)
            .ok_or_else(|| "Invalid curve point representation".into())
    }

    pub(crate) fn to_compressed_array(self) -> GenericArray<u8, CompressedPointSize> {
        GenericArray::<u8, CompressedPointSize>::from_exact_iter(
            self.0.to_affine().to_encoded_point(true).as_bytes().iter().cloned(),
        ).expect("An AffinePoint is composed of elements of the correct size and their slice repr fits in the `CompressedPointSize`-sized array.")
    }

    pub(crate) fn to_backend(self) -> BackendPoint {
        self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for Point {
    type Error = String;
    fn try_from(val: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_compressed_bytes(val)
    }
}

impl Serialize for Point {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SliceLike::<Hex>::serialize(&self.to_compressed_array(), serializer)
    }
}

impl<'de> Deserialize<'de> for Point {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SliceLike::<Hex>::deserialize(deserializer)
    }
}

impl From<u64> for Scalar {
    fn from(val: u64) -> Self {
        Self(BackendScalar::from(val))
    }
}

impl Neg for Scalar {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar(self.0.add(&other.0))
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar(self.0.add(&other.0))
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, other: &Scalar) {
        self.0.add_assign(&other.0)
    }
}

impl Add<Point> for Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        Point(self.0.add(&(other.0)))
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        Scalar(self.0.sub(&(other.0)))
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, other: &Scalar) {
        self.0.sub_assign(&other.0)
    }
}

impl Mul<Scalar> for Point {
    type Output = Point;

    fn mul(self, other: Scalar) -> Point {
        Point(self.0.mul(&(other.0)))
    }
}

impl Mul<&Scalar> for Point {
    type Output = Point;

    fn mul(self, other: &Scalar) -> Point {
        Point(self.0.mul(&(other.0)))
    }
}

impl Mul<&Scalar> for &Point {
    type Output = Point;

    fn mul(self, other: &Scalar) -> Point {
        Point(self.0.mul(&(other.0)))
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        Scalar(self.0.mul(&(other.0)))
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar(self.0.mul(&(other.0)))
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, other: &Scalar) {
        self.0.mul_assign(&other.0)
    }
}

impl core::iter::Sum for Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Self::ZERO)
    }
}

impl<'a> core::iter::Sum<&'a Self> for Scalar {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl core::iter::Product for Scalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Mul::mul).unwrap_or(Self::ONE)
    }
}

impl core::iter::Sum for Point {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Self::IDENTITY)
    }
}

impl<'a> core::iter::Sum<&'a Self> for Point {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

#[cfg(test)]
mod test {
    use super::Scalar;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    #[test]
    fn to_and_from_bytes() {
        let mut rng = ChaChaRng::from_seed([7u8; 32]);
        let s = Scalar::random(&mut rng);

        // Round trip works
        let bytes = s.to_be_bytes();
        let s_from_bytes = Scalar::try_from_be_bytes(&bytes).expect("bytes are valid");
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
