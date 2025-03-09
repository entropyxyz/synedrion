//! Parameters intended for testing, scaled down to small curve orders and integer sizes.

use crypto_bigint::{modular::MontyForm, nlimbs, NonZero, U1024, U128, U256, U512};
use elliptic_curve::{
    bigint::{self as bigintv05},
    Curve,
};
use serde::{Deserialize, Serialize};
use tiny_curve::TinyCurve32;

#[cfg(feature = "bip32")]
use ::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::{PublicKey, SecretKey},
    tiny_curve::{PrivateKeyBip32, PublicKeyBip32},
};

use crate::{
    cggmp21::{convert_uint, upcast_uint, SchemeParams},
    paillier::PaillierParams,
};

#[cfg(feature = "bip32")]
use crate::curve::{PublicTweakable, SecretTweakable};

type U128Mod = MontyForm<{ nlimbs!(128) }>;
type U256Mod = MontyForm<{ nlimbs!(256) }>;
type U512Mod = MontyForm<{ nlimbs!(512) }>;

/// Paillier parameters **for testing purposes only**.
/// Security is weakened to allow for faster execution.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    /*
    The prime size is chosen to be minimal for which the `TestSchemeParams` still work.
    In the presigning, we are effectively constructing a ciphertext of

        d = x * sum(j=1..P) y_i + sum(j=1..2*(P-1)) z_j

    where

        0 < x, y_i < q < 2^L, and
        -2^LP < z < 2^LP

    (`q` is the curve order, `L` and `LP` are constants in `TestSchemeParams`,
    `P` is the number of parties).
    This is `delta_i` or `chi_i`.

    During signing `chi_i` gets additionally multiplied by `r` (nonce, a scalar).

    We need the final result to be `-N/2 < d < N/2`
    (that is, it may be negative, and it cannot wrap around modulo N),
    so that it could fit in a Paillier ciphertext without wrapping around.
    This is needed for ZK proofs to work.

    `N` is a product of two primes of the size `PRIME_BITS`, so `N > 2^(2 * PRIME_BITS - 2)`.
    The upper bound on `log2(d * r)` is

        max(2 * L, LP + 2) + ceil(log2(CURVE_ORDER)) + ceil(log2(P))

    (note that in reality, due to numbers being random, the distribution will have a distinct peak,
    and the upper bound will have a low probability of being reached)

    Therefore we require

        max(2 * L, LP + 2) + ceil(log2(CURVE_ORDER)) + ceil(log2(P)) < 2 * PRIME_BITS - 2`

    For tests we assume `ceil(log2(P)) = 5` (we won't run tests with more than 32 nodes),
    and since in `TestSchemeParams` `L = LP = 256`, this leads to `PRIME_BITS >= 397`.

    For production it does not matter since 2*L, LP, and log2(CURVE_ORDER)
    are much smaller than 2*PRIME_BITS.
    */

    // TODO: `PRIME_BITS` should be 128 bits, but that doesn't work yet.
    // See https://github.com/entropyxyz/synedrion/pull/193#issuecomment-2703197306
    // and related issue #187.
    const PRIME_BITS: u32 = 127;
    type HalfUint = U128;
    type HalfUintMod = U128Mod;
    type Uint = U256;
    type UintMod = U256Mod;
    type WideUint = U512;
    type WideUintMod = U512Mod;
    type ExtraWideUint = U1024;
}

/// Scheme parameters **for testing purposes only**.
/// Security is weakened to allow for faster execution.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct TestParams;

// Some requirements from range proofs etc:
// - $П_{enc}$, safe two's complement representation of $\alpha$ requires
//   `L_BOUND + EPS_BOUND + 1 < Uint::BITS - 1`
// - $П_{enc}$, safe two's complement representation of $z_1$ requires
//   `L_BOUND + max(EPS_BOUND, log2(q)) + 1 < Uint::BITS - 1`
//   (where `q` is the curve order)
// - Range checks will fail with the probability $q / 2^\eps$, so $\eps$ should be large enough.
// - P^{fac} assumes $N ~ 2^{4 \ell + 2 \eps}$
impl SchemeParams for TestParams {
    type Curve = TinyCurve32;
    // TODO: ReprUint is typenum::U192 because of RustCrypto stack internals, hence the U384 here,
    // but once that is solved, this can be a U128 (or even smaller).
    type WideCurveUint = bigintv05::U384;
    const SECURITY_BITS: usize = 16;
    const SECURITY_PARAMETER: usize = 32;
    const L_BOUND: u32 = 32;
    const EPS_BOUND: u32 = 64;
    const LP_BOUND: u32 = 160;
    type Paillier = PaillierTest;
    const CURVE_ORDER: NonZero<<Self::Paillier as PaillierParams>::Uint> =
        convert_uint(upcast_uint(Self::Curve::ORDER))
            .to_nz()
            .expect("Correct by construction");
    const CURVE_ORDER_WIDE: NonZero<<Self::Paillier as PaillierParams>::WideUint> =
        convert_uint(upcast_uint(Self::Curve::ORDER))
            .to_nz()
            .expect("Correct by construction");
}

#[cfg(feature = "bip32")]
impl PublicTweakable for VerifyingKey<<TestParams as SchemeParams>::Curve> {
    type Bip32Pk = PublicKeyBip32<<TestParams as SchemeParams>::Curve>;
    fn tweakable_pk(&self) -> Self::Bip32Pk {
        let pk: PublicKey<_> = self.into();
        let wrapped_pk: PublicKeyBip32<_> = pk.into();
        wrapped_pk
    }
    fn key_from_tweakable_pk(pk: &Self::Bip32Pk) -> Self {
        VerifyingKey::from(pk.as_ref())
    }
}

#[cfg(feature = "bip32")]
impl SecretTweakable for SigningKey<<TestParams as SchemeParams>::Curve> {
    type Bip32Sk = PrivateKeyBip32<<TestParams as SchemeParams>::Curve>;

    fn tweakable_sk(&self) -> Self::Bip32Sk {
        let sk: SecretKey<_> = self.into();
        let wrapped_sk: PrivateKeyBip32<_> = sk.into();
        wrapped_sk
    }

    fn key_from_tweakable_sk(sk: &Self::Bip32Sk) -> Self {
        SigningKey::from(sk.as_ref())
    }
}
