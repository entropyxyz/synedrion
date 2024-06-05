use crypto_bigint::{
    modular::MontyForm, nlimbs, Encoding, Integer, RandomMod, Uint, Zero, U1024, U2048, U4096,
    U512, U8192,
};

use crate::tools::hashing::{Chain, Hashable};

pub(crate) const fn upcast_uint<const N1: usize, const N2: usize>(value: Uint<N1>) -> Uint<N2> {
    debug_assert!(N2 >= N1);
    let mut result_words = [0; N2];
    let mut i = 0;
    while i < N1 {
        result_words[i] = value.as_words()[i];
        i += 1;
    }
    Uint::from_words(result_words)
}

pub trait ToMod: Integer {
    fn to_mod(
        self,
        precomputed: &<<Self as Integer>::Monty as crypto_bigint::Monty>::Params,
    ) -> <Self as Integer>::Monty {
        <<Self as Integer>::Monty as crypto_bigint::Monty>::new(self, precomputed.clone())
    }
}

pub trait HasWide: Sized + Zero /*TODO: remove this ––> */ + core::fmt::Debug {
    type Wide: Integer + Encoding + RandomMod;
    fn mul_wide(&self, other: &Self) -> Self::Wide;
    fn square_wide(&self) -> Self::Wide;

    /// Converts `self` to a new `Wide` uint, setting the higher half to `0`s.
    /// Consumes `self`.
    // TODO: provide default impl here? Why not?
    fn into_wide(self) -> Self::Wide;

    /// Splits a `Wide` in two halves and returns the halves (`Self` sized) in a
    /// tuple (lower half first).
    ///
    /// *Note*: The behaviour of this method has changed in v0.2. Previously,
    /// the order of the halves was `(hi, lo)` but after v0.2 the order is `(lo,
    /// hi)`.
    fn from_wide(value: Self::Wide) -> (Self, Self);

    /// Tries to convert a `Wide` into a `Self` sized uint. Splits a `Wide`
    /// value in two halves and returns the lower half if the high half is zero.
    /// Otherwise returns `None`.
    fn try_from_wide(value: Self::Wide) -> Option<Self> {
        let (lo, hi) = Self::from_wide(value);
        if hi.is_zero().into() {
            return Some(lo);
        }
        None
    }
}

impl<const L: usize> Hashable for Uint<L>
where
    Uint<L>: Encoding,
{
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_constant_sized_bytes(&self.to_be_bytes())
    }
}

impl HasWide for U512 {
    type Wide = U1024;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn into_wide(self) -> Self::Wide {
        (self, Self::ZERO).into()
    }
    fn from_wide(value: Self::Wide) -> (Self, Self) {
        value.into()
    }
}

impl HasWide for U1024 {
    type Wide = U2048;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn into_wide(self) -> Self::Wide {
        (self, Self::ZERO).into()
    }
    fn from_wide(value: Self::Wide) -> (Self, Self) {
        value.into()
    }
}

impl HasWide for U2048 {
    type Wide = U4096;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn into_wide(self) -> Self::Wide {
        (self, Self::ZERO).into()
    }
    fn from_wide(value: Self::Wide) -> (Self, Self) {
        value.into()
    }
}

impl HasWide for U4096 {
    type Wide = U8192;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn into_wide(self) -> Self::Wide {
        (self, Self::ZERO).into()
    }
    fn from_wide(value: Self::Wide) -> (Self, Self) {
        value.into()
    }
}

// This is a dummy implementation to satisfy the compiler; the PaillierParams::ExtraWideUint
// "requires" a `HasWide` bound or `into_wide()` on a `WideUint` will fail to compile.
// TODO: dig deeper into wth is going on.
impl HasWide for U8192 {
    type Wide = U8192;
    fn mul_wide(&self, _other: &Self) -> Self::Wide {
        unimplemented!()
    }
    fn square_wide(&self) -> Self::Wide {
        unimplemented!()
    }
    fn into_wide(self) -> Self::Wide {
        unimplemented!()
    }
    fn from_wide(_value: Self::Wide) -> (Self, Self) {
        unimplemented!()
    }
}

pub type U512Mod = MontyForm<{ nlimbs!(512) }>;
pub type U1024Mod = MontyForm<{ nlimbs!(1024) }>;
pub type U2048Mod = MontyForm<{ nlimbs!(2048) }>;
pub type U4096Mod = MontyForm<{ nlimbs!(4096) }>;

impl ToMod for U512 {}
impl ToMod for U1024 {}
impl ToMod for U2048 {}
impl ToMod for U4096 {}
impl ToMod for U8192 {}
