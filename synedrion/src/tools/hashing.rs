use digest::{Digest, ExtendableOutput, Update};
use hashing_serializer::HashingSerializer;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Shake256, Shake256Reader};

use crate::curve::Scalar;
use crate::tools::serde_bytes;

/// A digest object that takes byte slices or decomposable ([`Hashable`]) objects.
pub trait Chain: Sized {
    type Digest: Update;

    fn as_digest_mut(&mut self) -> &mut Self::Digest;

    /// Hash raw bytes.
    ///
    /// Note: only for impls in specific types, do not use directly.
    fn chain_raw_bytes(self, bytes: &[u8]) -> Self;

    /// Hash a bytestring that is known to be constant-sized
    /// (e.g. byte representation of a built-in integer).
    fn chain_constant_sized_bytes(self, bytes: &(impl AsRef<[u8]> + ?Sized)) -> Self {
        self.chain_raw_bytes(bytes.as_ref())
    }

    /// Hash raw bytes in a collision-resistant way.
    fn chain_bytes(self, bytes: &(impl AsRef<[u8]> + ?Sized)) -> Self {
        // Hash the length too to prevent hash conflicts. (e.g. H(AB|CD) == H(ABC|D)).
        // Not strictly necessary for fixed-size arrays, but it's easier to just always do it.
        let len = (bytes.as_ref().len() as u64).to_be_bytes();
        self.chain_raw_bytes(&len).chain_raw_bytes(bytes.as_ref())
    }

    fn chain<T: Hashable>(self, hashable: &T) -> Self {
        hashable.chain(self)
    }

    fn chain_type<T: HashableType>(self) -> Self {
        T::chain_type(self)
    }

    fn chain_slice<T: Hashable>(self, hashable: &[T]) -> Self {
        // Hashing the length too to prevent collisions.
        let len = hashable.len() as u64;
        let mut digest = self.chain(&len);
        for elem in hashable {
            digest = digest.chain(elem);
        }
        digest
    }
}

pub(crate) type BackendDigest = Sha256;

/// Wraps a fixed output hash for easier replacement, and standardizes the use of DST.
pub(crate) struct FofHasher(BackendDigest);

impl Chain for FofHasher {
    type Digest = BackendDigest;

    fn as_digest_mut(&mut self) -> &mut Self::Digest {
        &mut self.0
    }

    fn chain_raw_bytes(self, bytes: &[u8]) -> Self {
        Self(self.0.chain_update(bytes))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct HashOutput(
    // Length of the BackendDigest output. Unfortunately we can't get it in compile-time.
    #[serde(with = "serde_bytes::as_hex")] pub(crate) [u8; 32],
);

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FofHasher {
    fn new() -> Self {
        Self(BackendDigest::new())
    }

    pub fn new_with_dst(dst: &[u8]) -> Self {
        Self::new().chain_bytes(dst)
    }

    pub(crate) fn finalize(self) -> HashOutput {
        HashOutput(self.0.finalize().into())
    }

    pub fn finalize_to_scalar(self) -> Scalar {
        Scalar::from_digest(self.0)
    }
}

/// Wraps an extendable output hash for easier replacement, and standardizes the use of DST.
pub struct XofHasher(Shake256);

impl Chain for XofHasher {
    type Digest = Shake256;

    fn as_digest_mut(&mut self) -> &mut Self::Digest {
        &mut self.0
    }

    fn chain_raw_bytes(self, bytes: &[u8]) -> Self {
        let mut digest = self.0;
        digest.update(bytes);
        Self(digest)
    }
}

impl XofHasher {
    fn new() -> Self {
        Self(Shake256::default())
    }

    pub fn new_with_dst(dst: &[u8]) -> Self {
        Self::new().chain_bytes(dst)
    }

    pub fn finalize_to_reader(self) -> Shake256Reader {
        self.0.finalize_xof()
    }
}

/// A trait allowing hashing of types without having access to their instances.
pub trait HashableType {
    fn chain_type<C: Chain>(digest: C) -> C;
}

/// A trait allowing complex objects to give access to their contents for hashing purposes
/// without the need of a conversion to a new form (e.g. serialization).
pub trait Hashable {
    fn chain<C: Chain>(&self, digest: C) -> C;
}

// We have a lot of things that already implement `Serialize`,
// so there's no point in implementing `Hashable` for them separately.
// The reproducibility of this hash depends on `serde` not breaking things,
// which we can be quite certain about - it is stable, and if it does break something,
// all the serialization will likely break too.
impl<T: Serialize> Hashable for T {
    fn chain<C: Chain>(&self, digest: C) -> C {
        let mut digest = digest;

        let serializer = HashingSerializer {
            digest: digest.as_digest_mut(),
        };

        // The only way it can return an error is if there is
        // some non-serializable element encountered, which is 100% reproducible
        // and will be caught in tests.
        self.serialize(serializer)
            .expect("The type is serializable");

        digest
    }
}
