use alloc::string::String;
use core::ops::{Add, Mul, Neg, Sub};
#[cfg(test)]
use crypto_bigint::Random;
use digest::XofReader;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    bounded::PackedBounded,
    subtle::{
        Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess,
        CtOption,
    },
    Bounded, CheckedAdd, CheckedSub, Encoding, HasWide, Integer, NonZero, RandomMod, ShlVartime,
    WrappingSub,
};

/// A packed representation for serializing Signed objects.
/// Usually they have the bound much lower than the full size of the integer,
/// so this way we avoid serializing a bunch of zeros.
#[derive(Serialize, Deserialize)]
struct PackedSigned {
    is_negative: bool,
    abs_value: PackedBounded,
}

impl<T> From<Signed<T>> for PackedSigned
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
    fn from(val: Signed<T>) -> Self {
        Self {
            is_negative: val.is_negative().into(),
            abs_value: PackedBounded::from(val.abs_bounded()),
        }
    }
}

impl<T> TryFrom<PackedSigned> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
    type Error = String;
    fn try_from(val: PackedSigned) -> Result<Self, Self::Error> {
        let abs_value = Bounded::try_from(val.abs_value)?;
        Self::new_from_abs(
            *abs_value.as_ref(),
            abs_value.bound(),
            Choice::from(val.is_negative as u8),
        )
        .ok_or_else(|| "Invalid values for the signed integer".into())
    }
}

/// A wrapper over unsigned integers that treats two's complement numbers as negative.
// In principle, Bounded could be separate from Signed, but we only use it internally,
// and pretty much every time we need a bounded value, it's also signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "PackedSigned",
    into = "PackedSigned",
    bound = "T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable"
)]

pub struct Signed<T> {
    /// bound on the bit size of the absolute value
    bound: u32,
    value: T,
}

impl<T> Signed<T>
where
    T: crypto_bigint::Bounded + Integer,
{
    fn checked_add(&self, rhs: &Self) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound) + 1;
        let in_range = bound.ct_lt(&T::BITS);

        let result = Self {
            bound,
            value: self.value.wrapping_add(&rhs.value),
        };
        let lhs_neg = self.is_negative();
        let rhs_neg = rhs.is_negative();
        let res_neg = result.is_negative();

        // Cannot get overflow from adding values of different signs,
        // and if for two values of the same sign the sign of the result remains the same
        // it means there was no overflow.
        CtOption::new(
            result,
            !(lhs_neg.ct_eq(&rhs_neg) & !lhs_neg.ct_eq(&res_neg)) & in_range,
        )
    }

    pub fn is_negative(&self) -> Choice {
        Choice::from(self.value.bit_vartime(T::BITS - 1) as u8)
    }

    pub fn bound(&self) -> u32 {
        self.bound
    }

    pub fn bound_usize(&self) -> usize {
        // Extracted into a method to localize the conversion
        self.bound as usize
    }

    /// Creates a signed value from an unsigned one,
    /// assuming that it encodes a positive value.
    pub fn new_positive(value: T, bound: u32) -> Option<Self> {
        // Reserving one bit as the sign bit (MSB)
        if bound >= T::BITS || value.bits() > bound {
            return None;
        }
        let result = Self { value, bound };
        if result.is_negative().into() {
            return None;
        }
        Some(result)
    }
}

impl<T> Signed<T>
where
    T: ConditionallySelectable + crypto_bigint::Bounded + Encoding + Integer,
{
    fn checked_mul(&self, rhs: &Self) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let in_range = bound.ct_lt(&T::BITS);

        let lhs_neg = self.is_negative();
        let rhs_neg = rhs.is_negative();
        let lhs = T::conditional_select(&self.value, &T::zero().wrapping_sub(&self.value), lhs_neg);
        let rhs = T::conditional_select(&rhs.value, &T::zero().wrapping_sub(&rhs.value), rhs_neg);
        let result = lhs.checked_mul(&rhs);
        let result_neg = lhs_neg ^ rhs_neg;
        result.and_then(|val| {
            let val_neg = T::zero().wrapping_sub(&val);
            let value = T::conditional_select(&val, &val_neg, result_neg);
            CtOption::new(Self { bound, value }, in_range)
        })
    }

    /// Performs the unary - operation.
    pub fn neg(&self) -> Self {
        Self {
            value: T::zero().wrapping_sub(&self.value),
            bound: self.bound,
        }
    }

    /// Computes the absolute value of [`self`]
    pub fn abs(&self) -> T {
        T::conditional_select(&self.value, &self.neg().value, self.is_negative())
    }

    // Asserts that the value lies in the interval `[-2^bound, 2^bound]`.
    // Panics if it is not the case.
    pub fn assert_bound(self, bound: usize) {
        assert!(
            T::one()
                .overflowing_shl_vartime(bound as u32)
                .map(|b| self.abs() <= b)
                .expect("Out of bounds"),
            "Out of bounds"
        );
    }

    /// Creates a [`Bounded`] from the absolute value of `self`.
    pub fn abs_bounded(&self) -> Bounded<T> {
        // Can unwrap here since the maximum bound on the positive Bounded
        // is always greater than the maximum bound on Signed
        Bounded::new(self.abs(), self.bound).expect(
            "Max bound for a positive Bounded is always greater than max bound for a Signed; qed",
        )
    }

    /// Creates a signed value from an unsigned one,
    /// treating it as if the sign is encoded in the MSB.
    pub fn new_from_unsigned(value: T, bound: u32) -> Option<Self> {
        let result = Self { value, bound };
        if bound >= T::BITS || result.abs().bits() > bound {
            return None;
        }
        Some(result)
    }

    /// Creates a signed value from an unsigned one, treating it as if it is the absolute value.
    /// Returns `None` if `abs_value` is actually negative or if the bounds are invalid.
    fn new_from_abs(abs_value: T, bound: u32, is_negative: Choice) -> Option<Self> {
        Self::new_positive(abs_value, bound).map(|x| {
            let mut x = x;
            x.conditional_negate(is_negative);
            x
        })
    }

    // Asserts that the value has bound less or equal to `bound`
    // (or, in other words, the value lies in the interval `(-(2^bound-1), 2^bound-1)`).
    // Returns the value with the bound set to `bound`.
    pub fn assert_bit_bound_usize(self, bound: usize) -> Option<Self> {
        if self.abs().bits_vartime() <= bound as u32 {
            Some(Self {
                value: self.value,
                bound: bound as u32,
            })
        } else {
            None
        }
    }
    /// Returns `true` if the value is within `[-2^bound_bits, 2^bound_bits]`.
    pub fn in_range_bits(&self, bound_bits: usize) -> bool {
        self.abs() <= T::one() << bound_bits
    }

    /// Returns a value in range `[-bound, bound]` derived from an extendable-output hash.
    ///
    /// This method should be used for deriving non-interactive challenges,
    /// since it is guaranteed to produce the same results on 32- and 64-bit platforms.
    ///
    /// Note: variable time in bit size of `bound`.
    pub fn from_xof_reader_bounded(rng: &mut impl XofReader, bound: &NonZero<T>) -> Self {
        let bound_bits = bound.as_ref().bits_vartime();
        assert!(bound_bits < <T as crypto_bigint::Bounded>::BITS);
        // Will not overflow because of the assertion above
        let positive_bound = bound
            .as_ref()
            .overflowing_shl_vartime(1)
            .expect("Just asserted that bound is smaller than precision; qed")
            .checked_add(&T::one())
            .unwrap();
        let positive_result = super::uint_from_xof(
            rng,
            &NonZero::new(positive_bound)
                .expect("Guaranteed to be greater than zero because we added 1"),
        );
        Self::new_from_unsigned(positive_result.wrapping_sub(bound.as_ref()), bound_bits)
            .expect("Guaranteed to be Some because we checked the bounds just above")
    }
}

#[cfg(test)]
impl<T> Signed<T>
where
    T: ConditionallySelectable + crypto_bigint::Bounded + Encoding + Integer + Random,
{
    /// Returns a random value in the whole available range,
    /// that is `[-(2^(BITS-1)-1), 2^(BITS-1)-1]`.
    #[cfg(test)]
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        loop {
            let value = T::random(rng);
            if value != T::one() << (T::BITS - 1) {
                return Self::new_from_unsigned(value, T::BITS - 1).unwrap();
            }
        }
    }
}

impl<T> Signed<T>
where
    T: ConditionallySelectable + crypto_bigint::Bounded + Encoding + Integer + RandomMod,
{
    /// Returns a random value in range `[-bound, bound]`.
    ///
    /// Note: variable time in bit size of `bound`.
    pub fn random_bounded(rng: &mut impl CryptoRngCore, bound: &NonZero<T>) -> Self {
        let bound_bits = bound.as_ref().bits_vartime();
        assert!(bound_bits < <T as crypto_bigint::Bounded>::BITS);
        // Will not overflow because of the assertion above
        let positive_bound = bound
            .as_ref()
            .overflowing_shl_vartime(1)
            .expect("Just asserted that bound is smaller than precision; qed")
            .checked_add(&T::one())
            .expect("Checked bounds above");
        let positive_result = T::random_mod(rng, &NonZero::new(positive_bound).unwrap());
        // Will not panic because of the assertion above
        Self::new_from_unsigned(positive_result.wrapping_sub(bound.as_ref()), bound_bits).unwrap()
    }

    /// Returns a random value in range `[-2^bound_bits, 2^bound_bits]`.
    ///
    /// Note: variable time in `bound_bits`.
    pub fn random_bounded_bits(rng: &mut impl CryptoRngCore, bound_bits: usize) -> Self {
        assert!(bound_bits < <T as crypto_bigint::Bounded>::BITS as usize - 1);
        let bound =
            NonZero::new(T::one() << bound_bits).expect("Checked bound_bits just above; qed");
        Self::random_bounded(rng, &bound)
    }
}

impl<T: Integer> Default for Signed<T> {
    fn default() -> Self {
        Self {
            bound: 0,
            value: T::default(),
        }
    }
}

impl<T> ConditionallySelectable for Signed<T>
where
    T: Integer + ConditionallySelectable,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            bound: u32::conditional_select(&a.bound, &b.bound, choice),
            value: T::conditional_select(&a.value, &b.value, choice),
        }
    }
}

impl<T> Neg for Signed<T>
where
    T: Integer + crypto_bigint::Bounded + ConditionallySelectable + Encoding,
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        Signed::neg(&self)
    }
}

impl<'a, T> Neg for &'a Signed<T>
where
    T: Integer + crypto_bigint::Bounded + ConditionallySelectable + Encoding,
{
    type Output = Signed<T>;
    fn neg(self) -> Self::Output {
        Signed::neg(self)
    }
}

impl<T> Signed<T>
where
    T: crypto_bigint::Bounded + HasWide + Integer,
    <T as HasWide>::Wide: RandomMod,
{
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and bit size of `scale`.
    pub fn random_bounded_bits_scaled(
        rng: &mut impl CryptoRngCore,
        bound_bits: usize,
        scale: &Bounded<T>,
    ) -> Signed<T::Wide> {
        assert!(
            (bound_bits as u32) < T::BITS - 1,
            "Out of bounds: bound_bits was {} but must be smaller than {}",
            bound_bits as u32,
            T::BITS - 1
        );
        let scaled_bound = scale
            .as_ref()
            .clone()
            .into_wide()
            .overflowing_shl_vartime(bound_bits as u32)
            .expect("Just asserted that bound bits is smaller than T's bit precision");

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .overflowing_shl_vartime(1)
            .expect("TODO: justify this properly")
            .checked_add(&T::Wide::one())
            .expect("TODO: justify this properly");
        let positive_result = T::Wide::random_mod(
            rng,
            &NonZero::new(positive_bound)
                .expect("Input guaranteed to be positive, i.e. it's non-zero"),
        );
        let result = positive_result.wrapping_sub(&scaled_bound);

        Signed {
            bound: bound_bits as u32 + scale.bound(),
            value: result,
        }
    }
}

impl<T> Signed<T>
where
    T: ConditionallySelectable + crypto_bigint::Bounded + HasWide + Encoding + Integer,
    T::Wide: ConditionallySelectable + crypto_bigint::Bounded,
{
    /// Returns a [`Signed`] with the same value, but twice the bit-width.
    /// Consumes `self`, but under the hood this method clones.
    pub fn into_wide(self) -> Signed<T::Wide> {
        let abs_result = self.abs().into_wide();
        Signed::new_from_abs(abs_result, self.bound(), self.is_negative()).unwrap()
    }

    /// Multiplies two [`Signed`] and returns a new [`Signed`] of twice the bit-width
    pub fn mul_wide(&self, rhs: &Self) -> Signed<T::Wide> {
        let abs_result = self.abs().mul_wide(&rhs.abs());
        Signed::new_from_abs(
            abs_result,
            // TODO(dp): This can overflow and looks a bit fishy to me. Should this be max(self_bound, rhs_bound) instead?
            self.bound() + rhs.bound(),
            self.is_negative() ^ rhs.is_negative(),
        )
        .expect("The call to new_positive cannot fail when the input is the absolute value ")
    }
}

impl<T> Signed<T>
where
    T: crypto_bigint::Bounded + HasWide + Integer,
    T::Wide: ConditionallySelectable + crypto_bigint::Bounded + HasWide,
{
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and `scale`.
    pub fn random_bounded_bits_scaled_wide(
        rng: &mut impl CryptoRngCore,
        bound_bits: usize,
        scale: &Bounded<T::Wide>,
    ) -> Signed<<T::Wide as HasWide>::Wide> {
        // TODO(dp): @reviewers: this is a bit nasty and feels wrong. Use try_from instead? Or go over all code and make types match?
        let bound_bits = bound_bits as u32;
        assert!(bound_bits < <T as crypto_bigint::Bounded>::BITS - 1);
        let scaled_bound = scale
            .as_ref()
            .into_wide()
            .overflowing_shl_vartime(bound_bits)
            .expect("Just asserted that bound_bits is smaller than bit precision of T");

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .overflowing_shl_vartime(1)
            .expect("TODO: justify this properly")
            .checked_add(&<T::Wide as HasWide>::Wide::one())
            .unwrap();
        let positive_result =
            <T::Wide as HasWide>::Wide::random_mod(rng, &NonZero::new(positive_bound).unwrap());
        let result = positive_result.wrapping_sub(&scaled_bound);

        Signed {
            bound: bound_bits + scale.bound(),
            value: result,
        }
    }
}

impl<T> Add<Signed<T>> for Signed<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(&rhs).unwrap()
    }
}

impl<T> Add<&Signed<T>> for Signed<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    type Output = Self;
    fn add(self, rhs: &Self) -> Self::Output {
        self.checked_add(rhs).unwrap()
    }
}

impl<T> CheckedSub<Signed<T>> for Signed<T>
where
    T: crypto_bigint::Bounded + ConditionallySelectable + Integer,
{
    /// Performs subtraction that returns `None` instead of wrapping around on underflow.
    /// The bound of the result is the bound of `self` (lhs).
    fn checked_sub(&self, rhs: &Signed<T>) -> CtOption<Self> {
        self.value.checked_sub(&rhs.value).and_then(|v| {
            let signed = Signed::new_positive(v, self.bound);
            if let Some(signed) = signed {
                CtOption::new(signed, 1u8.into())
            } else {
                CtOption::new(Signed::default(), 0u8.into())
            }
        })
    }
}

impl<T> Sub<Signed<T>> for Signed<T>
where
    T: crypto_bigint::Bounded + ConditionallySelectable + Encoding + Integer,
{
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_add(&-rhs).expect("Invalid subtraction")
    }
}

impl<T> Sub<&Signed<T>> for Signed<T>
where
    T: crypto_bigint::Bounded + ConditionallySelectable + Encoding + Integer,
{
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self::Output {
        self.checked_add(&-rhs).expect("Invalid subtraction")
    }
}

impl<T> Mul<Signed<T>> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(&rhs).unwrap()
    }
}

impl<T> Mul<&Signed<T>> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        self.checked_mul(rhs).unwrap()
    }
}

impl<T> core::iter::Sum for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x.checked_add(&y).unwrap())
            .unwrap_or(Self::default())
    }
}

impl<'a, T> core::iter::Sum<&'a Self> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl<T> PartialOrd for Signed<T>
where
    T: PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        // TODO(dp): Complete this by figuring out how to think about the bounds here. Are the bounds relevant at all for comparisons?
        self.value.partial_cmp(&other.value)
    }
}

#[cfg(test)]
mod tests {
    use super::Signed;
    use crate::uint::U1024;
    use crypto_bigint::CheckedSub;
    use rand::SeedableRng;
    use rand_chacha;
    use std::ops::Neg;
    const SEED: u64 = 123;

    #[test]
    fn neg_u1024() {
        // U1024 test vectors with bound set to 1023 in the form of tuples (signed, neg)
        let negged = vec![
            (
                Signed::new_from_unsigned(U1024::from_be_hex("303AF5B1E3C8854FA90BEE942901FFA83B4203EB238EE6942B08F2308ECBA2B83E3D1AFDF3BB4EDBDFF3D38BE44EE61A04E8CF1D0C7F0ED427E7A65CAEC05584C24551A7AF07122BBCD1A20ED37B59738669776A94704A6258E74999507F533FBBCB829FA821D84E55D82A221FA08FBB2AE6B0A1D47DD401DA7D2556E7302B93"), 1023).unwrap(),
                Signed::new_from_unsigned(U1024::from_be_hex("CFC50A4E1C377AB056F4116BD6FE0057C4BDFC14DC71196BD4F70DCF71345D47C1C2E5020C44B124200C2C741BB119E5FB1730E2F380F12BD81859A3513FAA7B3DBAAE5850F8EDD4432E5DF12C84A68C799688956B8FB59DA718B666AF80ACC044347D6057DE27B1AA27D5DDE05F7044D5194F5E2B822BFE2582DAA918CFD46D"), 1023).unwrap()),
            (
                Signed::new_from_unsigned(U1024::from_be_hex("9C34F7DCD7C4F13F595A5D11387ED8D50B6CA1977E96A87A6F60651B9C01619B78B7696305837AC60DC599FAC6207FA90D6EBF7E8B2A13975243526AD1AD0987A69102922AF0ECE0479A41D35321A8761145A1901FE06E4B8637ED024FB0F1D413BD95457F4EEAC4FD5EEDFE2EF366EAFC6D6BC33FA36B109492A7DD5999E2D4"), 1023).unwrap(),
                Signed::new_from_unsigned(U1024::from_be_hex("63CB0823283B0EC0A6A5A2EEC781272AF4935E6881695785909F9AE463FE9E648748969CFA7C8539F23A660539DF8056F291408174D5EC68ADBCAD952E52F678596EFD6DD50F131FB865BE2CACDE5789EEBA5E6FE01F91B479C812FDB04F0E2BEC426ABA80B1153B02A11201D10C99150392943CC05C94EF6B6D5822A6661D2C"),1023).unwrap()),
            (
                Signed::new_from_unsigned(U1024::from_be_hex("B2AD07365CA873172B5F7C0A6BE1471219BC5CC8C38E7041A3FAD02861C89A8E39A38CCDDBDAB95E3DE81061AC47B7F0C4DBE2CDABBEFE468775DB894100F5D94B21F93CE02030F58DCB12B176D9B12FF9F975C87E1CE2D072E29C5654E1AB56AECCC3B1B643AC39BA8067AB9B1C211868D57E685AD4A22275E9DA4C08A47BA1"), 1023).unwrap(),
                Signed::new_from_unsigned(U1024::from_be_hex("4D52F8C9A3578CE8D4A083F5941EB8EDE643A3373C718FBE5C052FD79E376571C65C7332242546A1C217EF9E53B8480F3B241D32544101B9788A2476BEFF0A26B4DE06C31FDFCF0A7234ED4E89264ED006068A3781E31D2F8D1D63A9AB1E54A951333C4E49BC53C6457F985464E3DEE7972A8197A52B5DDD8A1625B3F75B845F"),1023).unwrap()
            ),
            (
                Signed::new_from_unsigned(U1024::from_be_hex("941CC97B08BBCC06A90DD7841ADCD6A9F7EA712B07EFF65CBDD1FB633B99FDB27C22D8FB888058869A5AA9826888AE33824A4EC062D7FF0DDF5FAD774500731C7CEA72DECE5CE5996637B57139A1A7FB4A8E9A90C45C5C2E45C87CCA467B1F17959551DEED1D219DDF7A32C499B9685A21CCEAA3F57D85F64A7353AE267ABB9B"), 1023).unwrap(),
                Signed::new_from_unsigned(U1024::from_be_hex("6BE33684F74433F956F2287BE523295608158ED4F81009A3422E049CC466024D83DD2704777FA77965A5567D977751CC7DB5B13F9D2800F220A05288BAFF8CE383158D2131A31A6699C84A8EC65E5804B571656F3BA3A3D1BA378335B984E0E86A6AAE2112E2DE622085CD3B664697A5DE33155C0A827A09B58CAC51D9854465"),1023).unwrap()
            ),
            (
                Signed::new_from_unsigned(U1024::from_be_hex("EA98D935D9815088E068E8F0FD199C30139A5522F523411FEB5DB0F496C681323271C4FA8330B413E69891CE05FF9F60BDF75A8A668E6E8199696CAFDFE9CC256577FDDFAABFF7CCE6ED47B520FCB0620C03E27BC5ADB484313E8EF81B473259ED5216791B6DEB1E609EB61D0D3D1E903C7323EFDED9CC5214AFCAB8F3C3E416"), 1023).unwrap(),
                Signed::new_from_unsigned(U1024::from_be_hex("156726CA267EAF771F97170F02E663CFEC65AADD0ADCBEE014A24F0B69397ECDCD8E3B057CCF4BEC19676E31FA00609F4208A5759971917E66969350201633DA9A880220554008331912B84ADF034F9DF3FC1D843A524B7BCEC17107E4B8CDA612ADE986E49214E19F6149E2F2C2E16FC38CDC10212633ADEB5035470C3C1BEA"),1023).unwrap()
            ),
            (
                Signed::new_from_unsigned(U1024::from_be_hex("CF5E9664D77852F1D4FD77E9A3249F9D6F5B68934AC5F85DBA9C7995DABBC5F1DC047E719D8047AFDBE45605BA628CCFB93E9AB12FD58095D286D8DE344C0DBD31F620524CAB2937AD0533045DC486625CF17A03B9E9AC852AE6902D18AEC50396F2BED80DFB0B8DA103F19CDD69A0243621AE7031149C2DFF9F86E6896CA223"), 1023).unwrap(),
                Signed::new_from_unsigned(U1024::from_be_hex("30A1699B2887AD0E2B0288165CDB606290A4976CB53A07A24563866A25443A0E23FB818E627FB850241BA9FA459D733046C1654ED02A7F6A2D792721CBB3F242CE09DFADB354D6C852FACCFBA23B799DA30E85FC4616537AD5196FD2E7513AFC690D4127F204F4725EFC0E6322965FDBC9DE518FCEEB63D20060791976935DDD"),1023).unwrap()
            ),
            (
                Signed::new_from_unsigned(U1024::from_be_hex("190AB4B9A4D2BF44BBC65BEF59BE277E92C9D490509C1185F6EE71565942F4505662977CCDBDBBC983538BCCA2E10677DEEA894FB9833C1503E2FEE54AD448AE240F828AF355DBAA81F3CA29B22410D0903A6BCB7BA3926BB827938444C0F8D0AFE2E6BB62EE9E562B8C0F4101B81F3A64D984D9FFE6D0BEBF06925B15860E1A"), 1023).unwrap(),
                Signed::new_from_unsigned(U1024::from_be_hex("E6F54B465B2D40BB4439A410A641D8816D362B6FAF63EE7A09118EA9A6BD0BAFA99D6883324244367CAC74335D1EF988211576B0467CC3EAFC1D011AB52BB751DBF07D750CAA24557E0C35D64DDBEF2F6FC59434845C6D9447D86C7BBB3F072F501D19449D1161A9D473F0BEFE47E0C59B267B2600192F4140F96DA4EA79F1E6"),1023).unwrap()
            ),
            (
                Signed::new_from_unsigned(U1024::from_be_hex("EFF032C6717803C9DE4C02266B2437580578BA0C31761A6945AAA4C5172DED0A1BB24EA8DE69CC3E0FAD24E3A7981811804996D9CA90B2C45DA1A9E36BEC04BB85070894A25C11D07F9C419535FFE271858309EEA54A26FD29A724DC32EF938CEC66329E27160AADFAAB0289AEEF489266B6FA629FC911D4DFB8BD86C5E37694"), 1023).unwrap(),
                Signed::new_from_unsigned(U1024::from_be_hex("100FCD398E87FC3621B3FDD994DBC8A7FA8745F3CE89E596BA555B3AE8D212F5E44DB157219633C1F052DB1C5867E7EE7FB66926356F4D3BA25E561C9413FB447AF8F76B5DA3EE2F8063BE6ACA001D8E7A7CF6115AB5D902D658DB23CD106C731399CD61D8E9F5520554FD765110B76D9949059D6036EE2B204742793A1C896C"),1023).unwrap()
            ),
            (
                Signed::new_from_unsigned(U1024::from_be_hex("DD8D33431BFDFB7E0C977AF2E1F919ABA1400DCBD855C1F6E19911EA3E6D362B96D597480AB29240ED1E1F21E0D85309DAC8A3B96A5B0B29CD01605D983613D9D6C637A7AF430B06454CB328329931B659C7057F236A56C588EC171DC6ACB0A26568FADA60941DED558A495AE3010EAF15288C5AA03814B04DCC083FFC80A0AC"), 1023).unwrap(),
                Signed::new_from_unsigned(U1024::from_be_hex("2272CCBCE4020481F368850D1E06E6545EBFF23427AA3E091E66EE15C192C9D4692A68B7F54D6DBF12E1E0DE1F27ACF625375C4695A4F4D632FE9FA267C9EC262939C85850BCF4F9BAB34CD7CD66CE49A638FA80DC95A93A7713E8E239534F5D9A9705259F6BE212AA75B6A51CFEF150EAD773A55FC7EB4FB233F7C0037F5F54"),1023).unwrap()
            ),
        ];
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(SEED);
        for i in 0..negged.len() {
            let signed = Signed::<U1024>::random(&mut rng);
            assert_eq!(signed.neg(), negged[i].1);
            assert_eq!(negged[i].1.neg(), signed);
            assert_eq!(signed.neg().neg(), signed);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid subtraction")]
    fn sub_panics_on_underflow() {
        // Biggest allowed bound is 2^1023:
        // 0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000_16
        // Biggest/smallest Signed<U1024> is |2^1022|:
        // 0x4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000_16
        let max_uint = U1024::from_be_hex("4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let one_signed = Signed::new_from_abs(U1024::ONE, U1024::BITS - 1, 0u8.into()).unwrap();
        let min_signed = Signed::new_from_abs(max_uint, U1024::BITS - 1, 1u8.into()).unwrap();
        let _ = min_signed - one_signed;
    }

    #[test]
    fn checked_sub_handles_underflow() {
        // Biggest/smallest Signed<U1024> is |2^1022|
        let max_uint = U1024::from_be_hex("4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let min_signed = Signed::new_from_abs(max_uint, U1024::BITS - 1, 1u8.into()).unwrap();
        let one_signed = Signed::new_from_abs(U1024::ONE, U1024::BITS - 1, 0u8.into()).unwrap();

        let result = min_signed.checked_sub(&one_signed);
        assert!(bool::from(result.is_none()))
    }
}
