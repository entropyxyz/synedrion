//! This module is an adapter to the ECC backend.
//! `elliptic_curves` has a somewhat unstable API,
//! and we isolate all the related logic here.

use core::default::Default;
use core::ops::{Add, Mul, Sub};

use k256::elliptic_curve::{
    bigint::U256, // Note that this type is different from typenum::U256
    hash2curve::{ExpandMsgXmd, GroupDigest},
    ops::Reduce,
    sec1::ToEncodedPoint,
    subtle::ConstantTimeEq,
    AffineXCoordinate,
    Field,
    FieldSize,
};
use k256::FieldBytes;
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::Digest, Sha256};

use crate::tools::hashing::{Chain, Hashable};

pub(crate) type BackendScalar = k256::Scalar;
pub(crate) type BackendNonZeroScalar = k256::NonZeroScalar;
pub(crate) type BackendPoint = k256::ProjectivePoint;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Scalar(BackendScalar);

impl Scalar {
    const ZERO: Self = Self(BackendScalar::ZERO);
    const ONE: Self = Self(BackendScalar::ONE);

    pub fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(BackendScalar::random(rng))
    }

    pub fn pow(&self, exp: usize) -> Self {
        let mut result = Self::ONE;
        for _ in 0..exp {
            result = &result * self;
        }
        result
    }

    pub fn from_digest(d: impl Digest<OutputSize = FieldSize<k256::Secp256k1>>) -> Self {
        // There's currently no way to make the required digest output size
        // depend on the target scalar size, so we are hardcoding it to 256 bit
        // (that is, equal to the scalar size).
        Self(<BackendScalar as Reduce<U256>>::from_be_bytes_reduced(
            d.finalize(),
        ))
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

pub(crate) fn zero_sum_scalars(rng: &mut (impl CryptoRng + RngCore), size: usize) -> Vec<Scalar> {
    // CHECK: do they all have to be non-zero?

    debug_assert!(size > 1);

    let mut scalars = (0..(size - 1))
        .map(|_| Scalar::random(rng))
        .collect::<Vec<_>>();
    let sum: Scalar = scalars
        .iter()
        .cloned()
        .reduce(|s1, s2| s1 + s2)
        .unwrap_or(Scalar::ZERO);
    scalars.push(-sum);
    scalars
}

#[derive(Clone)]
pub struct NonZeroScalar(BackendNonZeroScalar);

impl NonZeroScalar {
    /// Generates a random non-zero scalar (in nearly constant-time).
    pub fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(BackendNonZeroScalar::random(rng))
    }

    pub fn into_scalar(self) -> Scalar {
        Scalar(*self.0)
    }

    pub fn from_digest(d: impl Digest<OutputSize = FieldSize<k256::Secp256k1>>) -> Self {
        // There's currently no way to make the required digest output size
        // depend on the target scalar size, so we are hardcoding it to 256 bit
        // (that is, equal to the scalar size).
        Self(<BackendNonZeroScalar as Reduce<U256>>::from_be_bytes_reduced(d.finalize()))
    }

    pub fn to_bytes(&self) -> FieldBytes {
        self.0.as_ref().to_bytes()
    }
}

impl From<NonZeroScalar> for Scalar {
    fn from(source: NonZeroScalar) -> Self {
        Scalar(*source.0)
    }
}

impl From<&NonZeroScalar> for Scalar {
    fn from(source: &NonZeroScalar) -> Self {
        Scalar(*source.0)
    }
}

impl PartialEq<NonZeroScalar> for NonZeroScalar {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point(BackendPoint);

impl Point {
    pub const GENERATOR: Self = Self(BackendPoint::GENERATOR);

    pub const IDENTITY: Self = Self(BackendPoint::IDENTITY);

    /// Hashes arbitrary data with the given domain separation tag
    /// into a valid EC point of the specified curve, using the algorithm described in the
    /// [IETF hash-to-curve standard](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/)
    pub fn from_data(dst: &[u8], data: &[&[u8]]) -> Option<Self> {
        Some(Self(
            k256::Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(data, dst).ok()?,
        ))
    }

    pub fn to_bytes(self) -> Box<[u8]> {
        self.0.to_affine().to_encoded_point(true).as_bytes().into()
    }
}

impl<C: Chain> Hashable<C> for Point {
    fn chain(&self, digest: C) -> C {
        digest.chain(&self.to_bytes())
    }
}

impl Default for Point {
    fn default() -> Self {
        Point::IDENTITY
    }
}

impl From<usize> for Scalar {
    fn from(val: usize) -> Self {
        // TODO: add a check that usize <= u64?
        Self(BackendScalar::from(val as u64))
    }
}

impl core::ops::Neg for Scalar {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar(self.0.add(other.0))
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar(self.0.add(&(other.0)))
    }
}

impl Add<&NonZeroScalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &NonZeroScalar) -> Scalar {
        Scalar(self.0.add(&(*other.0)))
    }
}

impl Add<&Scalar> for &NonZeroScalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar(self.0.add(&other.0))
    }
}

impl Add<&NonZeroScalar> for &NonZeroScalar {
    type Output = Scalar;

    fn add(self, other: &NonZeroScalar) -> Scalar {
        Scalar(self.0.add(&(*other.0)))
    }
}

impl Add<&Point> for &Point {
    type Output = Point;

    fn add(self, other: &Point) -> Point {
        Point(self.0.add(&(other.0)))
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar(self.0.sub(&(other.0)))
    }
}

impl Sub<&NonZeroScalar> for &NonZeroScalar {
    type Output = Scalar;

    fn sub(self, other: &NonZeroScalar) -> Scalar {
        Scalar(self.0.sub(&(*other.0)))
    }
}

impl Mul<&Scalar> for &Point {
    type Output = Point;

    fn mul(self, other: &Scalar) -> Point {
        Point(self.0.mul(&(other.0)))
    }
}

impl Mul<&NonZeroScalar> for &Point {
    type Output = Point;

    fn mul(self, other: &NonZeroScalar) -> Point {
        Point(self.0.mul(&(*other.0)))
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar(self.0.mul(&(other.0)))
    }
}

impl Mul<&NonZeroScalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &NonZeroScalar) -> Scalar {
        Scalar(self.0.mul(&(*other.0)))
    }
}

impl Mul<&NonZeroScalar> for &NonZeroScalar {
    type Output = NonZeroScalar;

    fn mul(self, other: &NonZeroScalar) -> NonZeroScalar {
        NonZeroScalar(self.0.mul(other.0))
    }
}

pub fn point_to_scalar(point: &Point) -> NonZeroScalar {
    // TODO: the operation is defined as acting on G\{infinity point}.
    // should we check in runitme? Make a NonInfinityPoint type?
    debug_assert!(point != &Point::IDENTITY);

    // TODO: check that it's the right thing to do, cryptographically speaking.
    NonZeroScalar(
        <BackendNonZeroScalar as Reduce<U256>>::from_be_bytes_reduced(point.0.to_affine().x()),
    )
}
