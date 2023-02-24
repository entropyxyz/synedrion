use digest::XofReader;
use rand_core::{CryptoRng, RngCore};

use crypto_bigint::{
    modular::runtime_mod::DynResidue, nlimbs, CtChoice, Encoding, Integer, RandomMod, Zero, U128,
    U64,
};
use crypto_primes::RandomPrimeWithRng;

use crate::tools::hashing::{Chain, HashInto, Hashable};

pub trait Uint: Zero + Integer + RandomMod + RandomPrimeWithRng {
    fn sub(&self, rhs: &Self) -> Self;
    fn add(&self, rhs: &Self) -> Self;
    fn mul(&self, rhs: &Self) -> Self;
    fn mul_wide(&self, rhs: &Self) -> (Self, Self);
    fn inv_odd_mod(&self, modulus: &Self) -> (Self, CtChoice);
    fn inv_mod2k(&self, k: usize) -> Self;
    fn trailing_zeros(&self) -> usize;
    fn bits(&self) -> usize;

    fn safe_prime_with_rng(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        <Self as RandomPrimeWithRng>::safe_prime_with_rng(rng, Self::BITS)
    }
}

impl Uint for U64 {
    fn sub(&self, rhs: &Self) -> Self {
        self.wrapping_sub(rhs)
    }

    fn add(&self, rhs: &Self) -> Self {
        self.wrapping_add(rhs)
    }

    fn mul(&self, rhs: &Self) -> Self {
        self.wrapping_mul(rhs)
    }

    fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        self.mul_wide(rhs)
    }

    fn inv_odd_mod(&self, modulus: &Self) -> (Self, CtChoice) {
        self.inv_odd_mod(modulus)
    }

    fn inv_mod2k(&self, k: usize) -> Self {
        self.inv_mod2k(k)
    }

    fn trailing_zeros(&self) -> usize {
        (*self).trailing_zeros()
    }

    fn bits(&self) -> usize {
        (*self).bits()
    }
}

impl Uint for U128 {
    fn sub(&self, rhs: &Self) -> Self {
        self.wrapping_sub(rhs)
    }

    fn add(&self, rhs: &Self) -> Self {
        self.wrapping_add(rhs)
    }

    fn mul(&self, rhs: &Self) -> Self {
        self.wrapping_mul(rhs)
    }

    fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        self.mul_wide(rhs)
    }

    fn inv_odd_mod(&self, modulus: &Self) -> (Self, CtChoice) {
        self.inv_odd_mod(modulus)
    }

    fn inv_mod2k(&self, k: usize) -> Self {
        self.inv_mod2k(k)
    }

    fn trailing_zeros(&self) -> usize {
        (*self).trailing_zeros()
    }

    fn bits(&self) -> usize {
        (*self).bits()
    }
}

impl Hashable for U128 {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_constant_sized_bytes(&self.to_be_bytes())
    }
}

impl Hashable for DynResidue<{ nlimbs!(128) }> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        // TODO: I don't think we really need `retrieve()` here,
        // but `DynResidue` objects are not serializable at the moment.
        digest.chain(&self.retrieve())
    }
}

impl HashInto for U128 {
    fn from_reader(reader: &mut impl XofReader) -> Self {
        let mut array = [0u8; 16];
        reader.read(&mut array);
        Self::from_be_bytes(array)
    }
}