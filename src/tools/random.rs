use rand_core::{OsRng, RngCore};

pub fn random_bits(min_bits: usize) -> Box<[u8]> {
    let len = (min_bits - 1) / 8 + 1; // minimum number of bytes containing `min_bits` bits.
    let mut bytes = vec![0; len];
    OsRng.fill_bytes(&mut bytes);
    bytes.into()
}
