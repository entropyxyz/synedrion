use alloc::boxed::Box;

use digest::{ExtendableOutput, Update, XofReader};
use hashing_serializer::HashingSerializer;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};

use crate::params::SchemeParams;

/// A digest object that takes byte slices or decomposable ([`Hashable`]) objects.
pub trait Chain: Sized {
    fn as_digest_mut(&mut self) -> &mut impl Update;

    /// Hash raw bytes.
    ///
    /// Note: only for impls in specific types, do not use directly.
    fn chain_raw_bytes(self, bytes: &[u8]) -> Self;

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
}

/// Wraps an extendable output hash for easier replacement, and standardizes the use of DST.
pub struct Hasher<P: SchemeParams>(P::Digest);

impl<P: SchemeParams> Chain for Hasher<P> {
    fn as_digest_mut(&mut self) -> &mut impl Update {
        &mut self.0
    }

    fn chain_raw_bytes(self, bytes: &[u8]) -> Self {
        let mut digest = self.0;
        digest.update(bytes);
        Self(digest)
    }
}

impl<P: SchemeParams> Hasher<P> {
    fn new() -> Self {
        Self(P::Digest::default())
    }

    pub fn new_with_dst(dst: &[u8]) -> Self {
        Self::new().chain_bytes(dst)
    }

    pub fn finalize_to_reader(self) -> <P::Digest as ExtendableOutput>::Reader {
        self.0.finalize_xof()
    }

    /// Finalizes into enough bytes to bring the collision probability to what's required by the scheme's security.
    pub fn finalize(self) -> HashOutput {
        // A common heuristic for hashes is that the log2 of the collision probability is half the output size.
        // We may not have enough output bytes, but this constitutes the best effort.
        HashOutput(self.0.finalize_xof().read_boxed((P::SECURITY_BITS * 2).div_ceil(8)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashOutput(#[serde(with = "SliceLike::<Hex>")] Box<[u8]>);

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
        self.serialize(serializer).expect("The type is serializable");

        digest
    }
}
