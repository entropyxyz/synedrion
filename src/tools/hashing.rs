use digest::{Digest, ExtendableOutput, Output, Update};
use sha2::Sha256;
use sha3::Shake256;

use super::group::{NonZeroScalar, Scalar};

/// Encodes the object into bytes for hashing purposes.
pub trait HashEncoding: Sized {
    type Repr: AsRef<[u8]> + Clone + Sized;
    fn to_hashable_bytes(&self) -> Self::Repr;
}

/// A digest object that takes byte slices or decomposable ([`Hashable`]) objects.
pub trait Chain: Sized {
    /// Hash raw bytes.
    ///
    /// Note: only for impls in specific types, do not use directly.
    fn chain_raw_bytes(self, bytes: &[u8]) -> Self;

    /// Hash raw bytes in a collision-resistant way.
    fn chain_bytes<T: AsRef<[u8]>>(self, bytes: T) -> Self {
        // Hash the length too to prevent hash conflicts. (e.g. H(AB|CD) == H(ABC|D)).
        // Not strictly necessary for fixed-size arrays, but it's easier to just always do it.
        let len = (bytes.as_ref().len() as u32).to_be_bytes();
        self.chain_raw_bytes(&len).chain_raw_bytes(bytes.as_ref())
    }

    fn chain(self, hashable: &impl Hashable<Self>) -> Self {
        hashable.chain(self)
    }
}

/// Wraps a fixed output hash for easier replacement, and standardizes the use of DST.
pub struct Hash(Sha256);

impl Chain for Hash {
    fn chain_raw_bytes(self, bytes: &[u8]) -> Self {
        Self(self.0.chain_update(bytes))
    }
}

impl Hash {
    fn new() -> Self {
        Self(Sha256::new())
    }

    pub fn new_with_dst(dst: &[u8]) -> Self {
        Self::new().chain_bytes(dst)
    }

    pub fn finalize(self) -> Output<Sha256> {
        self.0.finalize()
    }

    pub fn finalize_to_scalar(self) -> Scalar {
        Scalar::from_digest(self.0)
    }

    pub fn finalize_to_nz_scalar(self) -> NonZeroScalar {
        NonZeroScalar::from_digest(self.0)
    }
}

/// Wraps an extendable output hash for easier replacement, and standardizes the use of DST.
pub struct XOFHash(Shake256);

impl Chain for XOFHash {
    fn chain_raw_bytes(self, bytes: &[u8]) -> Self {
        let mut digest = self.0;
        digest.update(bytes);
        Self(digest)
    }
}

impl XOFHash {
    fn new() -> Self {
        Self(Shake256::default())
    }

    pub fn new_with_dst(dst: &[u8]) -> Self {
        Self::new().chain_bytes(dst)
    }

    pub fn finalize_boxed(self, output_size: usize) -> Box<[u8]> {
        self.0.finalize_boxed(output_size)
    }
}

/// A trait allowing complex objects to give access to their contents for hashing purposes
/// without the need of a conversion to a new form (e.g. serialization).
pub trait Hashable<C: Chain> {
    fn chain(&self, digest: C) -> C;
}

// NOTE: we *do not* want to implement Hashable for `usize` to prevent hashes being different
// on different targets.
impl<C: Chain> Hashable<C> for u32 {
    fn chain(&self, digest: C) -> C {
        digest.chain_bytes(self.to_be_bytes())
    }
}

impl<C: Chain> Hashable<C> for Box<[u8]> {
    fn chain(&self, digest: C) -> C {
        digest.chain_bytes(self)
    }
}

impl<C: Chain> Hashable<C> for &[u8] {
    fn chain(&self, digest: C) -> C {
        digest.chain_bytes(self)
    }
}

impl<C: Chain, const N: usize> Hashable<C> for [u8; N] {
    fn chain(&self, digest: C) -> C {
        digest.chain_bytes(self)
    }
}

impl<C: Chain, T: HashEncoding> Hashable<C> for T {
    fn chain(&self, digest: C) -> C {
        let bytes = self.to_hashable_bytes();
        digest.chain_bytes(&bytes)
    }
}

impl<C: Chain, T1: Hashable<C>, T2: Hashable<C>> Hashable<C> for (&T1, &T2) {
    fn chain(&self, digest: C) -> C {
        digest.chain(self.0).chain(self.1)
    }
}

impl<C: Chain, T1: Hashable<C>, T2: Hashable<C>, T3: Hashable<C>> Hashable<C> for (&T1, &T2, &T3) {
    fn chain(&self, digest: C) -> C {
        digest.chain(self.0).chain(self.1).chain(self.2)
    }
}

impl<C: Chain, T: Hashable<C>> Hashable<C> for Vec<T> {
    fn chain(&self, digest: C) -> C {
        // Hashing the vector length too to prevent collisions.
        let len = self.len() as u32;
        let mut digest = digest.chain(&len);
        for elem in self {
            digest = digest.chain(elem);
        }
        digest
    }
}
