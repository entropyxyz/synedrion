use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// A helper wrapper for managing secret values.
///
/// On top of `secrecy::SecretBox` functionality, it provides:
/// - Safe `Clone` implementation (without needing to impl `CloneableSecret`)
/// - Safe `Debug` implementation
/// - Safe serialization/deserialization (down to `serde` API; what happens there we cannot control)
pub(crate) struct Secret<T: Zeroize>(SecretBox<T>);

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(SecretBox::init_with(|| self.0.expose_secret().clone()))
    }
}

impl<T: Zeroize + Serialize> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.expose_secret().serialize(serializer)
    }
}

impl<'de, T: Zeroize + Clone + Deserialize<'de>> Deserialize<'de> for Secret<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(SecretBox::try_init_with(|| T::deserialize(deserializer))?))
    }
}

impl<T: Zeroize> Debug for Secret<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret<{}>(...)", core::any::type_name::<T>())
    }
}

impl<T: Zeroize> From<SecretBox<T>> for Secret<T> {
    fn from(value: SecretBox<T>) -> Self {
        Self(value)
    }
}

impl<T: Zeroize> Deref for Secret<T> {
    type Target = SecretBox<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
