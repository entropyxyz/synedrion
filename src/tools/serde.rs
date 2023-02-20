use core::any::type_name;
use core::fmt;
use core::marker::PhantomData;

use serde::{de, Deserializer, Serializer};

/// A trait providing a way to construct an object from a byte slice.
pub trait TryFromBytes: Sized {
    /// The error returned on construction failure.
    type Error: fmt::Display;

    /// Attempts to construct an object from a byte slice.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
}

/// Serialize an object representable as bytes using `0x`-prefixed hex encoding
/// if the target format is human-readable, and plain bytes otherwise.
pub fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_bytes(obj.as_ref())
}

struct BytesVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for BytesVisitor<T>
where
    T: TryFromBytes,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", type_name::<T>())
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        T::try_from_bytes(v).map_err(de::Error::custom)
    }
}

/// Deserialize an object representable as bytes assuming `0x`-prefixed hex encoding
/// if the source format is human-readable, and plain bytes otherwise.
pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TryFromBytes,
{
    deserializer.deserialize_bytes(BytesVisitor::<T>(PhantomData))
}
