use alloc::boxed::Box;
use alloc::vec;
use core::ops::BitXorAssign;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::tools::serde_bytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BitVec(#[serde(with = "serde_bytes::as_base64")] Box<[u8]>);

impl BitVec {
    pub fn random(rng: &mut impl CryptoRngCore, min_bits: usize) -> Self {
        let len = (min_bits - 1) / 8 + 1; // minimum number of bytes containing `min_bits` bits.
        let mut bytes = vec![0; len];
        rng.fill_bytes(&mut bytes);
        Self(bytes.into())
    }

    pub fn xor_all<'a>(bitvecs: impl Iterator<Item = &'a Self>) -> Self {
        let mut bitvecs = bitvecs;
        let mut result = bitvecs.next().unwrap().clone();
        for bitvec in bitvecs {
            result ^= bitvec;
        }
        result
    }
}

impl BitXorAssign<&BitVec> for BitVec {
    fn bitxor_assign(&mut self, rhs: &BitVec) {
        assert!(self.0.len() == rhs.0.len());
        for i in 0..self.0.len() {
            self.0[i] ^= rhs.0[i];
        }
    }
}
