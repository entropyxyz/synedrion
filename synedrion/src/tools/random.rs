use alloc::boxed::Box;
use alloc::vec;

use rand_core::CryptoRngCore;

pub fn random_bits(rng: &mut impl CryptoRngCore, min_bits: usize) -> Box<[u8]> {
    let len = (min_bits - 1) / 8 + 1; // minimum number of bytes containing `min_bits` bits.
    let mut bytes = vec![0; len];
    rng.fill_bytes(&mut bytes);
    bytes.into()
}
