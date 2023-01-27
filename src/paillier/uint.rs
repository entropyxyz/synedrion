use crypto_bigint::{Integer, RandomMod, Zero, U128, U64};
use crypto_primes::safe_prime;

pub trait Uint: Zero + Integer + RandomMod {
    fn sub(&self, rhs: &Self) -> Self;
    fn safe_prime() -> Self;
    fn mul_wide(&self, rhs: &Self) -> (Self, Self);
}

impl Uint for U64 {
    fn sub(&self, rhs: &Self) -> Self {
        self.wrapping_sub(rhs)
    }

    fn safe_prime() -> Self {
        safe_prime(Self::BITS)
    }

    fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        self.mul_wide(&rhs)
    }
}

impl Uint for U128 {
    fn sub(&self, rhs: &Self) -> Self {
        self.wrapping_sub(rhs)
    }

    fn safe_prime() -> Self {
        safe_prime(Self::BITS)
    }

    fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        self.mul_wide(&rhs)
    }
}
