#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    // TODO (#76): handle unwraps gracefully and enable this lint
    // clippy::unwrap_used,
    missing_docs,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]

extern crate alloc;

// Expose interal entities for benchmarks
#[cfg(feature = "bench-internals")]
pub mod bench_internals;

mod cggmp21;
mod common;
mod constructors;
mod curve;
mod entities;
mod paillier;
mod rounds;
pub mod sessions;
mod threshold;
mod tools;
mod uint;
mod www02;

// Some re-exports to avoid the need for version-matching
pub use k256;
pub use k256::ecdsa;
pub use signature;

pub use cggmp21::{
    InteractiveSigningError, InteractiveSigningProof, InteractiveSigningResult, KeyGenError,
    KeyGenProof, KeyGenResult, KeyInitError, KeyInitResult, KeyRefreshResult, PresigningError,
    PresigningProof, PresigningResult, ProductionParams, SchemeParams, SigningProof, SigningResult,
    TestParams,
};
pub use constructors::{
    make_interactive_signing_session, make_key_gen_session, make_key_init_session,
    make_key_refresh_session, make_key_resharing_session, KeyResharingInputs, NewHolder, OldHolder,
    PrehashedMessage,
};
pub use curve::RecoverableSignature;
pub use entities::{
    KeyShare, KeyShareChange, KeyShareSeed, ThresholdKeyShare, ThresholdKeyShareSeed,
};
pub use rounds::ProtocolResult;
pub use sessions::{CombinedMessage, FinalizeOutcome, MappedResult, Session};
pub use www02::KeyResharingResult;

// TODO: find a proper home for this. Used by signed.rs and cggmp21::sigma::mod_.rs
pub(crate) mod misc {
    use crate::uint::{Encoding, Integer, NonZero, PowBoundedExp, Signed};
    use crypto_bigint::{
        subtle::{ConditionallySelectable, CtOption},
        Invert,
    };
    use digest::XofReader;
    // Build a `T` integer from an extendable Reader function
    pub(crate) fn from_xof<T>(reader: &mut impl XofReader, modulus: &NonZero<T>) -> T
    where
        T: Integer + Encoding,
    {
        let backend_modulus = modulus.as_ref();

        let n_bits = backend_modulus.bits_vartime();
        let n_bytes = (n_bits + 7) / 8; // ceiling division by 8

        // If the number of bits is not a multiple of 8,
        // use a mask to zeroize the high bits in the gererated random bytestring,
        // so that we don't have to reject too much.
        let mask = if n_bits & 7 != 0 {
            (1 << (n_bits & 7)) - 1
        } else {
            u8::MAX
        };

        let mut bytes = T::zero().to_le_bytes();
        loop {
            reader.read(&mut (bytes.as_mut()[0..n_bytes as usize]));
            bytes.as_mut()[n_bytes as usize - 1] &= mask;
            let n = T::from_le_bytes(bytes);

            if n.ct_lt(backend_modulus).into() {
                return n;
            }
        }
    }

    pub(crate) fn pow_signed<T>(
        uint: <T as Integer>::Monty,
        exponent: &Signed<T>,
    ) -> <T as Integer>::Monty
    where
        T: Integer + crypto_bigint::Bounded + Encoding + ConditionallySelectable,
        T::Monty: Invert<Output = CtOption<<T as Integer>::Monty>> + ConditionallySelectable,
    {
        let abs_exponent = exponent.abs();
        let abs_result = uint.pow_bounded_exp(&abs_exponent, exponent.bound());
        let inv_result = abs_result.invert().expect("TODO: justify this properly");
        <T as Integer>::Monty::conditional_select(&abs_result, &inv_result, exponent.is_negative())
    }

    // TODO:
    // pow_signed_wide
    // pow_signed_extra_wide
    // pow_signed_vartime
}
