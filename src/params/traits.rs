use core::{fmt::Debug, ops::Add};

// We're depending on a pre-release `crypto-bigint` version,
// and `k256` depends on the released one.
// So as long as that is the case, `k256` `Uint` is separate
// from the one used throughout the crate.
use crypto_bigint::{subtle::ConditionallySelectable, Bounded, Integer, PowBoundedExp, RandomMod};
use digest::{ExtendableOutput, Update};
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use elliptic_curve::{
    bigint::{self as bigintv05, Concat, Split},
    generic_array::ArrayLength,
    point::DecompressPoint,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, PrimeCurve, PrimeField,
};
use serde::Serialize;
use zeroize::Zeroize;

use crate::{
    curve::chain_curve,
    paillier::{chain_paillier_params, PaillierParams},
    tools::hashing::Chain,
    uint::{BoxedEncoding, Extendable},
};

/// Signing scheme parameters.
pub trait SchemeParams: 'static + Debug + Clone + Send + PartialEq + Eq + Send + Sync + Ord + Copy + Serialize
where
    <Self::Curve as CurveArithmetic>::ProjectivePoint: FromEncodedPoint<Self::Curve>,
    <Self::Curve as Curve>::FieldBytesSize: ModulusSize,
    <<Self as SchemeParams>::Curve as CurveArithmetic>::AffinePoint: ToEncodedPoint<Self::Curve>
        + FromEncodedPoint<Self::Curve>
        + DecompressPoint<Self::Curve>
        + VerifyPrimitive<Self::Curve>,
    <Self::Curve as CurveArithmetic>::Scalar: SignPrimitive<Self::Curve> + Ord,
    <<Self::Curve as Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    <Self::Curve as Curve>::Uint: Concat<Output = Self::WideCurveUint>,
{
    /// The elliptic curve (of prime order) used.
    type Curve: CurveArithmetic + PrimeCurve + DigestPrimitive;
    /// Double the curve Scalar-width integer type.
    type WideCurveUint: bigintv05::Integer + Split<Output = <Self::Curve as Curve>::Uint>;

    /// The hash that will be used for protocol's internal purposes.
    ///
    /// Note: the collision probability must be consistent with [`Self::SECURITY_BITS`].
    type Digest: Default + Update + ExtendableOutput;

    /// The number of bits of security provided by the scheme.
    const SECURITY_BITS: usize; // $m$ in the paper
    /// The scheme's statistical security parameter.
    const SECURITY_PARAMETER: usize; // $\kappa$ in the paper
    /// The bound for secret values.
    const L_BOUND: u32; // $\ell$, paper sets it to $\log2(q)$ (see Table 2)
    /// The error bound for secret masks.
    const LP_BOUND: u32; // $\ell^\prime$, in paper $= 5 \ell$ (see Table 2)
    /// The error bound for range checks (referred to in the paper as the slackness parameter).
    const EPS_BOUND: u32; // $\eps$, in paper $= 2 \ell$ (see Table 2)
    /// The parameters of the Paillier encryption.
    type Paillier: PaillierParams<
        WideUint: Extendable<Self::ExtraWideUint>,
        Uint: Integer<Monty: PowBoundedExp<Self::ExtraWideUint>>,
    >;

    /// An integer that fits the squared RSA modulus times a small factor.
    /// Used in some ZK proofs.
    type ExtraWideUint: Bounded + ConditionallySelectable + Integer + RandomMod + BoxedEncoding + Zeroize;

    /// Evaluates to ``true`` if the parameters satisfy a set of inequalities
    /// required for them to be used for the CGGMP scheme.
    const SELF_CONSISTENT: bool =
        // See Appendix C.1
        <Self::Curve as CurveArithmetic>::Scalar::NUM_BITS == Self::SECURITY_PARAMETER as u32
        && Self::L_BOUND >= Self::SECURITY_PARAMETER as u32
        && Self::EPS_BOUND >= Self::L_BOUND + Self::SECURITY_PARAMETER as u32
        && Self::LP_BOUND >= Self::L_BOUND * 3 + Self::EPS_BOUND
        && Self::Paillier::MODULUS_BITS >= Self::LP_BOUND + Self::EPS_BOUND
        // This one is not mentioned in C.1, but is required by $П^{fac}$ (Fig. 26)
        // (it says $\approx$, not $=$, but it is not clear how approximately this should hold,
        // so to be on the safe side we require equality).
        && Self::L_BOUND * 2 + Self::EPS_BOUND == Self::Paillier::PRIME_BITS
        // Make sure the calculations in `П^{fac}` fit into `ExtraWideUint`
        // In that proof, we are sampling a random in range `∈ ±2^(L + EPS) * N^2`
        // and adding a much smaller number to it, so the absolute value of the result is
        // `< 2^(L + EPS + MODULUS_BITS * 2)`.
        // Therefore `ExtraWideUint::BITS` must fit `L + EPS + MODULUS_BITS * 2` bits,
        // and we make it strictly greater to accommodate 1 bit for the sign.
        && Self::ExtraWideUint::BITS > Self::Paillier::MODULUS_BITS * 2 + Self::L_BOUND + Self::EPS_BOUND;
}

pub(crate) fn chain_scheme_params<P, C>(digest: C) -> C
where
    P: SchemeParams,
    C: Chain,
{
    let digest = chain_curve::<P::Curve, _>(digest);
    let digest = chain_paillier_params::<P::Paillier, _>(digest);
    digest
        .chain_bytes(&(P::SECURITY_BITS as u32).to_be_bytes())
        .chain_bytes(&(P::SECURITY_PARAMETER as u32).to_be_bytes())
        .chain_bytes(&P::L_BOUND.to_be_bytes())
        .chain_bytes(&P::LP_BOUND.to_be_bytes())
        .chain_bytes(&P::EPS_BOUND.to_be_bytes())
}
