use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::ops::BitXorAssign;

use digest::XofReader;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Base64, SliceLike};

#[derive(Serialize, Deserialize)]
struct PackedBitVec {
    bits: u32,
    #[serde(with = "SliceLike::<Base64>")]
    byte_vec: Box<[u8]>,
}

impl TryFrom<PackedBitVec> for BitVec {
    type Error = String;
    fn try_from(source: PackedBitVec) -> Result<Self, Self::Error> {
        if source.bits.div_ceil(8) as usize > source.byte_vec.len() {
            return Err("The declared number of bits is greater than the size of the byte string".into());
        }
        let bits = source
            .bits
            .try_into()
            .map_err(|_| "The number of bits does not fit into `usize`")?;
        Ok(BitVec::from_bytes_unchecked(bits, &source.byte_vec))
    }
}

impl From<BitVec> for PackedBitVec {
    fn from(source: BitVec) -> Self {
        let bytes = source.0.len().div_ceil(8);
        let mut byte_vec = vec![0u8; bytes];

        // Allowing direct indexing since we set the correct vector length above.
        #[allow(clippy::indexing_slicing)]
        for (i, bit) in source.0.iter().enumerate() {
            let byte_position = i / 8;
            let bit_mask = 1 << (7 - (i % 8));
            if *bit {
                byte_vec[byte_position] |= bit_mask;
            }
        }

        Self {
            bits: source.0.len() as u32,
            byte_vec: byte_vec.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PackedBitVec", into = "PackedBitVec")]
pub(crate) struct BitVec(Box<[bool]>);

impl BitVec {
    fn from_bytes_unchecked(bits: usize, byte_vec: &[u8]) -> Self {
        debug_assert!(bits.div_ceil(8) <= byte_vec.len());
        let mut bit_vec = Vec::with_capacity(bits);

        // Allowing direct indexing since we checked the vector length above.
        #[allow(clippy::indexing_slicing)]
        for i in 0..bits {
            let byte_position = i / 8;
            let bit_mask = 1 << (7 - (i % 8));
            bit_vec.push(byte_vec[byte_position] & bit_mask != 0);
        }

        Self(bit_vec.into())
    }

    pub fn random(rng: &mut dyn CryptoRngCore, bits: usize) -> Self {
        let bytes = bits.div_ceil(8);
        let mut byte_vec = vec![0; bytes];
        rng.fill_bytes(&mut byte_vec);
        Self::from_bytes_unchecked(bits, &byte_vec)
    }

    pub fn bits(&self) -> &[bool] {
        &self.0
    }

    pub fn from_xof_reader(reader: &mut impl XofReader, bits: usize) -> Self {
        let bytes = bits.div_ceil(8);
        let mut byte_vec = vec![0u8; bytes];
        reader.read(&mut byte_vec);
        Self::from_bytes_unchecked(bits, &byte_vec)
    }
}

impl BitXorAssign<&BitVec> for BitVec {
    fn bitxor_assign(&mut self, rhs: &BitVec) {
        assert!(self.0.len() == rhs.0.len());
        for (lhs, rhs) in self.0.iter_mut().zip(rhs.0.iter()) {
            *lhs ^= rhs
        }
    }
}
