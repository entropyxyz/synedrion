use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use digest::{Digest, ExtendableOutput, Update, XofReader};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::Shake256;

use super::group::Scalar;

/// Encodes the object into bytes for hashing purposes.
pub trait HashInto {
    fn from_reader(reader: &mut impl XofReader) -> Self;
}

/// A digest object that takes byte slices or decomposable ([`Hashable`]) objects.
pub trait Chain: Sized {
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
        let len = (bytes.as_ref().len() as u32).to_be_bytes();
        self.chain_raw_bytes(&len).chain_raw_bytes(bytes.as_ref())
    }

    fn chain<T: Hashable>(self, hashable: &T) -> Self {
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

// TODO: this may be more widely applicable than just in HashOutput
fn serdect_serialize<S, T>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: AsRef<[u8]>,
{
    serdect::array::serialize_hex_lower_or_bin(val, serializer)
}

fn serdect_deserialize<'de, D, T, const N: usize>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: From<[u8; N]>,
{
    let mut buffer = [0; N];
    serdect::array::deserialize_hex_or_bin(&mut buffer, deserializer)?;
    Ok(buffer.into())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct HashOutput(
    #[serde(serialize_with = "serdect_serialize")]
    #[serde(deserialize_with = "serdect_deserialize")]
    [u8; 32], // Length of the Sha256 output. Unfortunately we can't get it in compile-time.
);

impl Hash {
    fn new() -> Self {
        Self(Sha256::new())
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
pub struct XofHash(Shake256);

impl Chain for XofHash {
    fn chain_raw_bytes(self, bytes: &[u8]) -> Self {
        let mut digest = self.0;
        digest.update(bytes);
        Self(digest)
    }
}

impl XofHash {
    fn new() -> Self {
        Self(Shake256::default())
    }

    pub fn new_with_dst(dst: &[u8]) -> Self {
        Self::new().chain_bytes(dst)
    }

    pub fn finalize_boxed(self, output_size: usize) -> Box<[u8]> {
        self.0.finalize_boxed(output_size)
    }

    pub fn finalize_reader(self) -> <Shake256 as ExtendableOutput>::Reader {
        self.0.finalize_xof()
    }
}

/// A trait allowing complex objects to give access to their contents for hashing purposes
/// without the need of a conversion to a new form (e.g. serialization).
pub trait Hashable {
    fn chain<C: Chain>(&self, digest: C) -> C;
}

// NOTE: we *do not* want to implement Hashable for `usize` to prevent hashes being different
// on different targets.
impl Hashable for u32 {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_constant_sized_bytes(&self.to_be_bytes())
    }
}

// TODO: we use it for Vec<bool>. Inefficient, but works for now.
// Replace with packing boolean vectors into bytes, perhaps? Maybe there is a crate for that.
impl Hashable for bool {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_constant_sized_bytes(if *self { b"\x01" } else { b"\x00" })
    }
}

impl Hashable for Box<[u8]> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_bytes(self)
    }
}

impl Hashable for &[u8] {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_bytes(self)
    }
}

impl<const N: usize> Hashable for [u8; N] {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_bytes(self)
    }
}

impl<T1: Hashable, T2: Hashable> Hashable for (&T1, &T2) {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(self.0).chain(self.1)
    }
}

impl<T1: Hashable, T2: Hashable, T3: Hashable> Hashable for (&T1, &T2, &T3) {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(self.0).chain(self.1).chain(self.2)
    }
}

impl<T: Hashable> Hashable for Vec<T> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        // Hashing the vector length too to prevent collisions.
        let len = self.len() as u32;
        let mut digest = digest.chain(&len);
        for elem in self {
            digest = digest.chain(elem);
        }
        digest
    }
}

impl<K: Hashable, V: Hashable> Hashable for BTreeMap<K, V> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        // Hashing the map length too to prevent collisions.
        let len = self.len() as u32;
        let mut digest = digest.chain(&len);
        // The iteration is ordered (by keys)
        for (key, value) in self {
            digest = digest.chain(key);
            digest = digest.chain(value);
        }
        digest
    }
}

impl Hashable for HashOutput {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_constant_sized_bytes(&self.0)
    }
}
