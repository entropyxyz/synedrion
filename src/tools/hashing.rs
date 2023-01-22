use sha2::digest::{Digest, Output};
use sha2::Sha256;

use super::group::{NonZeroScalar, Point, Scalar};

// Our hash of choice.
pub(crate) type BackendDigest = Sha256;

// Wraps BackendDigest for easier replacement, and standardizes the use of DST.
pub struct Hash(BackendDigest);

impl Hash {
    fn new() -> Self {
        Self(BackendDigest::new())
    }

    pub fn new_with_dst(dst: &[u8]) -> Self {
        let dst_len = (dst.len() as u32).to_be_bytes();
        Self::new().chain_update(dst_len).chain_update(dst)
    }

    /// Hash raw bytes.
    /// Note: if you are hashing a variable-sized bytestring, hash its length too
    /// to prevent hash conflicts. (e.g. H(AB|CD) == H(ABC|D))
    fn chain_update<T: AsRef<[u8]>>(self, bytes: T) -> Self {
        Self(self.0.chain_update(bytes.as_ref()))
    }

    pub fn chain(self, hashable: &impl Hashable) -> Self {
        hashable.chain(self)
    }

    pub fn finalize(self) -> Output<BackendDigest> {
        self.0.finalize()
    }

    pub fn finalize_to_scalar(self) -> Scalar {
        Scalar::from_digest(self.0)
    }

    pub fn finalize_to_nz_scalar(self) -> NonZeroScalar {
        NonZeroScalar::from_digest(self.0)
    }
}

pub trait Hashable {
    fn chain(&self, digest: Hash) -> Hash;
}

impl<T: Hashable> Hashable for &T {
    fn chain(&self, hash: Hash) -> Hash {
        hash.chain(*self)
    }
}

impl<T1: Hashable, T2: Hashable> Hashable for (T1, T2) {
    fn chain(&self, hash: Hash) -> Hash {
        hash.chain(&self.0).chain(&self.1)
    }
}

impl<T1: Hashable, T2: Hashable, T3: Hashable> Hashable for (T1, T2, T3) {
    fn chain(&self, hash: Hash) -> Hash {
        hash.chain(&self.0).chain(&self.1).chain(&self.2)
    }
}

impl Hashable for Point {
    fn chain(&self, hash: Hash) -> Hash {
        hash.chain_update(&self.to_bytes())
    }
}

impl Hashable for usize {
    fn chain(&self, hash: Hash) -> Hash {
        hash.chain_update(&self.to_be_bytes())
    }
}

impl<T: Hashable> Hashable for Vec<T> {
    fn chain(&self, hash: Hash) -> Hash {
        let mut digest = hash.chain(&self.len());
        for elem in self {
            digest = digest.chain(elem);
        }
        digest
    }
}

impl Hashable for Vec<u8> {
    fn chain(&self, hash: Hash) -> Hash {
        hash.chain(&self.len()).chain_update(self)
    }
}

impl Hashable for &[u8] {
    fn chain(&self, hash: Hash) -> Hash {
        hash.chain(&self.len()).chain_update(self)
    }
}
