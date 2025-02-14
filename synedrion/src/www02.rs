mod entities;
pub(crate) mod key_resharing;

#[cfg(feature = "bip32")]
pub use bip32::DeriveChildKey;
pub use entities::ThresholdKeyShare;
pub use key_resharing::{KeyResharing, KeyResharingProtocol, NewHolder, OldHolder};

#[cfg(feature = "bip32")]
mod bip32;
