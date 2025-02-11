use crypto_bigint::{Bounded, Encoding, Integer};
use digest::{Digest, ExtendableOutput, Update, XofReader};
use hashing_serializer::HashingSerializer;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{ArrayLike, Hex};
use sha2::Sha256;
use sha3::{Shake256, Shake256Reader};

/// A digest object that takes byte slices or decomposable ([`Hashable`]) objects.
pub trait Chain: Sized {
    type Digest: Update;

    fn as_digest_mut(&mut self) -> &mut Self::Digest;

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
    #[serde(with = "ArrayLike::<Hex>")] pub(crate) [u8; 32],
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
        self.serialize(serializer).expect("The type is serializable");

        digest
    }
}

pub(crate) fn uint_from_xof<T>(reader: &mut impl XofReader, n_bits: u32) -> T
where
    T: Integer + Bounded + Encoding,
{
    assert!(n_bits <= T::BITS);
    let n_bytes = n_bits.div_ceil(8) as usize;

    // If the number of bits is not a multiple of 8, use a mask to zeroize the high bits in the
    // gererated random bytestring, so that we don't have to reject too much.
    let mask = if n_bits & 7 != 0 {
        (1 << (n_bits & 7)) - 1
    } else {
        u8::MAX
    };

    let mut bytes = T::zero().to_le_bytes();
    let buf = bytes
        .as_mut()
        .get_mut(0..n_bytes)
        .expect("`n_bytes` does not exceed `T::BYTES` as asserted above");
    reader.read(buf);
    bytes.as_mut().last_mut().map(|byte| {
        *byte &= mask;
        Some(byte)
    });
    T::from_le_bytes(bytes)
}
