use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    Integer, NonZero, RandomMod, Uint, U128, U64,
};
use crypto_primes::safe_prime;
use rand_core::{OsRng, RngCore};

pub trait PaillierParams {
    type Prime;
    type Modulus;

    fn safe_prime() -> Self::Prime;
    fn mul_wide(x: &Self::Prime, y: &Self::Prime) -> Self::Modulus;
}

struct PaillierTest;

impl PaillierParams for PaillierTest {
    type Prime = U64;
    type Modulus = U128;

    fn safe_prime() -> Self::Prime {
        safe_prime(Self::Prime::BITS)
    }

    fn mul_wide(x: &Self::Prime, y: &Self::Prime) -> Self::Modulus {
        let (hi, lo) = x.mul_wide(&y);
        (lo, hi).into()
    }
}

pub struct SecretKeyPaillier<P: PaillierParams> {
    p: P::Prime,
    q: P::Prime,
}

impl<P: PaillierParams> SecretKeyPaillier<P> {
    pub fn random() -> Self {
        let p = P::safe_prime();
        let q = P::safe_prime();

        Self { p, q }
    }

    /*
    /// Euler's totient function of `p * q` - the number of positive integers up to `p * q`
    /// that are relatively prime to it.
    /// Since `p` and `q` are primes, returns `(p - 1) * (q - 1)`.
    pub fn totient(&self) -> Uint<L2> {
        let (hi, lo) = (self.p.wrapping_sub(&Uint::<L>::ONE))
            .mul_wide(&(self.q.wrapping_sub(&Uint::<L>::ONE)));
        (lo, hi).into()
    }*/

    pub fn public_key(&self) -> PublicKeyPaillier<P> {
        PublicKeyPaillier {
            modulus: P::mul_wide(&self.p, &self.q),
        }
    }
}

pub struct PublicKeyPaillier<P: PaillierParams> {
    /// N
    modulus: P::Modulus,
}

/*
impl<const L2: usize> PublicKeyPaillier<L2> {
    pub fn modulus(&self) -> Uint<L2> {
        self.modulus
    }
}
*/

#[cfg(test)]
mod tests {
    use super::{PaillierTest, SecretKeyPaillier};

    #[test]
    fn basics() {
        let sk = SecretKeyPaillier::<PaillierTest>::random();
        //let pk = sk.public_key();
    }
}
