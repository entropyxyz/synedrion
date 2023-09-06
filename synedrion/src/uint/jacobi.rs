//! Jacobi symbol calculation.

use crypto_bigint::{Integer, NonZero, Uint, Word, Zero};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JacobiSymbol {
    Zero,
    One,
    MinusOne,
}

impl core::ops::Neg for JacobiSymbol {
    type Output = Self;
    fn neg(self) -> Self {
        match self {
            Self::Zero => Self::Zero,
            Self::One => Self::MinusOne,
            Self::MinusOne => Self::One,
        }
    }
}

impl core::ops::Mul<JacobiSymbol> for JacobiSymbol {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        match (self, other) {
            (Self::One, Self::One) => Self::One,
            (Self::MinusOne, Self::MinusOne) => Self::One,
            (Self::MinusOne, Self::One) => Self::MinusOne,
            (Self::One, Self::MinusOne) => Self::MinusOne,
            _ => Self::Zero,
        }
    }
}

// A helper trait to generalize some functions over Word and Uint.
trait SmallMod {
    fn mod8(&self) -> Word;
    fn mod4(&self) -> Word;
    fn trailing_zeros(&self) -> usize;
}

impl SmallMod for Word {
    fn mod8(&self) -> Word {
        self & 7
    }
    fn mod4(&self) -> Word {
        self & 3
    }
    fn trailing_zeros(&self) -> usize {
        Word::trailing_zeros(*self) as usize
    }
}

impl<const L: usize> SmallMod for Uint<L> {
    fn mod8(&self) -> Word {
        self.as_limbs()[0].0 & 7
    }
    fn mod4(&self) -> Word {
        self.as_limbs()[0].0 & 3
    }
    fn trailing_zeros(&self) -> usize {
        Uint::<L>::trailing_zeros(self)
    }
}

/// Transforms `(a/p)` -> `(r/p)` for odd `p`, where the resulting `r` is odd, and `a = r * 2^s`.
/// Takes a Jacobi symbol value, and returns `r` and the new Jacobi symbol,
/// negated if the transformation changes parity.
///
/// Note that the returned `r` is odd.
fn reduce_numerator<T>(j: JacobiSymbol, a: &T, p: &T) -> (JacobiSymbol, T)
where
    T: SmallMod,
    for<'a> &'a T: core::ops::Shr<usize, Output = T>,
{
    let p_mod_8 = p.mod8();
    let s = a.trailing_zeros();
    let j = if (s & 1) == 1 && (p_mod_8 == 3 || p_mod_8 == 5) {
        -j
    } else {
        j
    };
    (j, a >> s)
}

/// Transforms `(a/p)` -> `(p/a)` for odd and coprime `a` and `p`.
/// Takes a Jacobi symbol value, and returns the swapped pair and the new Jacobi symbol,
/// negated if the transformation changes parity.
fn swap<T: SmallMod>(j: JacobiSymbol, a: T, p: T) -> (JacobiSymbol, T, T) {
    let j = if a.mod4() == 1 || p.mod4() == 1 {
        j
    } else {
        -j
    };
    (j, p, a)
}

pub trait JacobiSymbolTrait {
    fn jacobi_symbol(&self, p: &Self) -> JacobiSymbol;
}

impl JacobiSymbolTrait for Word {
    fn jacobi_symbol(&self, p: &Self) -> JacobiSymbol {
        if *p & 1 == 0 {
            panic!("`p` must be an odd integer");
        }

        let mut result = JacobiSymbol::One; // Keep track of all the sign flips here.
        let mut a = *self;
        let mut p = *p;

        while a != 0 {
            // At this point `p` is odd (either coming from outside of the loop,
            // or from the previous iteration, where a previously reduced `a`
            // was swapped into its place), so we can call this.
            (result, a) = reduce_numerator(result, &a, &p);
            // At this point both `a` and `p` are odd: `p` was odd before,
            // and `a` is odd after `reduce_numerator()`.
            // Note that technically `swap()` only returns a valid `result`
            // if `a` and `p` are coprime.
            // But if they are not, we will return `Zero` eventually,
            // which is not affected by any sign changes.
            (result, a, p) = swap(result, a, p);
            a %= p;
        }
        if p == 1 {
            result
        } else {
            JacobiSymbol::Zero
        }
    }
}

impl<const L: usize> JacobiSymbolTrait for Uint<L> {
    fn jacobi_symbol(&self, p: &Self) -> JacobiSymbol {
        if p.is_even().into() {
            panic!("`p` must be an odd integer");
        }

        let mut result = JacobiSymbol::One; // Keep track of all the sign flips here.
        let mut a = *self;
        let mut p = *p;

        while (!a.is_zero()).into() {
            (result, a) = reduce_numerator(result, &a, &p);
            (result, a, p) = swap(result, a, p);
            a = a.rem(&NonZero::new(p).unwrap());

            if p.bits() <= Word::BITS as usize {
                return result * a.as_words()[0].jacobi_symbol(&p.as_words()[0]);
            }
        }
        if p == Uint::<L>::ONE {
            result
        } else {
            JacobiSymbol::Zero
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{Encoding, Random, Word, U128};
    use num_bigint::BigUint;
    use num_modular::ModularSymbols;
    use rand_core::OsRng;

    use super::{JacobiSymbol, JacobiSymbolTrait};

    // Reference from `num-modular` - supports long `p`, but only positive `a`.
    fn jacobi_symbol_ref(a: &Word, p: &Word) -> JacobiSymbol {
        match a.jacobi(p) {
            1 => JacobiSymbol::One,
            -1 => JacobiSymbol::MinusOne,
            0 => JacobiSymbol::Zero,
            _ => unreachable!(),
        }
    }

    fn jacobi_symbol_ref_uint(a: &U128, p: &U128) -> JacobiSymbol {
        let a_bi = BigUint::from_bytes_be(a.to_be_bytes().as_ref());
        let p_bi = BigUint::from_bytes_be(p.to_be_bytes().as_ref());
        match a_bi.jacobi(&p_bi) {
            1 => JacobiSymbol::One,
            -1 => JacobiSymbol::MinusOne,
            0 => JacobiSymbol::Zero,
            _ => unreachable!(),
        }
    }

    #[test]
    fn small_values() {
        // Test small values, using a reference implementation.
        for a in 0u64..31 {
            for p in (1u64..31).step_by(2) {
                let j_ref = jacobi_symbol_ref(&a, &p);
                let j = Word::jacobi_symbol(&a, &p);
                assert_eq!(j, j_ref, "({a}/{p}): ref = {j_ref:?}, actual = {j:?}");
            }
        }
    }

    #[test]
    fn big_values() {
        // Test small values, using a reference implementation.
        for _ in 0..100 {
            let a = U128::random(&mut OsRng);
            let p = U128::random(&mut OsRng) | U128::ONE;
            let j_ref = jacobi_symbol_ref_uint(&a, &p);
            let j = U128::jacobi_symbol(&a, &p);
            assert_eq!(j, j_ref, "({a}/{p}): ref = {j_ref:?}, actual = {j:?}");
        }
    }
}
