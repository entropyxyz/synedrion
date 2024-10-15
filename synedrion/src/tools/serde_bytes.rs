//! Convenience functions to serialize byte sequences efficiently
//! both in binary and human-readable formats.
//! TODO (#83): make a separate crate.

use alloc::format;
use core::any::type_name;
use core::fmt;
use core::marker::PhantomData;

use base64::{engine::general_purpose, Engine as _};
use serde::{de, Deserializer, Serializer};

enum Encoding {
    /// Use base64 representation for byte arrays.
    Base64,
    /// Use hex representation for byte arrays.
    Hex,
}

// A type of a trait alias, to work around https://github.com/rust-lang/rust/issues/113517
// If not for that issue, we could just use `TryFrom<&'a [u8]>` directly in the bounds.
pub(crate) trait TryFromBytes<'a, E>: TryFrom<&'a [u8], Error = E> {}

impl<'a, T> TryFromBytes<'a, T::Error> for T where T: TryFrom<&'a [u8]> {}

struct B64Visitor<T, V>(PhantomData<T>, PhantomData<V>);

impl<T, V> de::Visitor<'_> for B64Visitor<T, V>
where
    T: for<'a> TryFromBytes<'a, V>,
    V: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b64-encoded {} bytes", type_name::<T>())
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = general_purpose::STANDARD_NO_PAD
            .decode(v)
            .map_err(de::Error::custom)?;
        T::try_from(&bytes).map_err(de::Error::custom)
    }
}

struct HexVisitor<T, V>(PhantomData<T>, PhantomData<V>);

impl<T, V> de::Visitor<'_> for HexVisitor<T, V>
where
    T: for<'a> TryFromBytes<'a, V>,
    V: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x-prefixed hex-encoded bytes of {}", type_name::<T>())
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() < 2 {
            return Err(de::Error::invalid_length(
                v.len(),
                &"0x-prefixed hex-encoded bytes",
            ));
        }
        if &v[..2] != "0x" {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(v),
                &"0x-prefixed hex-encoded bytes",
            ));
        }
        let bytes = hex::decode(&v[2..]).map_err(de::Error::custom)?;
        T::try_from(&bytes).map_err(de::Error::custom)
    }
}

struct BytesVisitor<T, V>(PhantomData<T>, PhantomData<V>);

impl<T, V> de::Visitor<'_> for BytesVisitor<T, V>
where
    T: for<'a> TryFromBytes<'a, V>,
    V: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", type_name::<T>())
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        T::try_from(v).map_err(de::Error::custom)
    }
}

/// A helper function that will serialize a byte array efficiently
/// depending on whether the target format is text or binary based.
fn serialize_with_encoding<T, S>(
    obj: &T,
    serializer: S,
    encoding: Encoding,
) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    if serializer.is_human_readable() {
        let encoded = match encoding {
            Encoding::Base64 => general_purpose::STANDARD_NO_PAD.encode(obj.as_ref()),
            Encoding::Hex => format!("0x{}", hex::encode(obj.as_ref())),
        };
        serializer.serialize_str(&encoded)
    } else {
        serializer.serialize_bytes(obj.as_ref())
    }
}

/// A helper function that will deserialize from a byte array,
/// matching the format used by [`serde_serialize`].
fn deserialize_with_encoding<'de, T, V, D>(
    deserializer: D,
    encoding: Encoding,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: for<'a> TryFromBytes<'a, V>,
    V: fmt::Display,
{
    if deserializer.is_human_readable() {
        match encoding {
            Encoding::Base64 => {
                deserializer.deserialize_str(B64Visitor::<T, V>(PhantomData, PhantomData))
            }
            Encoding::Hex => {
                deserializer.deserialize_str(HexVisitor::<T, V>(PhantomData, PhantomData))
            }
        }
    } else {
        deserializer.deserialize_bytes(BytesVisitor::<T, V>(PhantomData, PhantomData))
    }
}

pub(crate) mod as_hex {
    //! A module containing serialization and deserialization function
    //! that use hex (`0x`-prefixed) representation for bytestrings in human-readable formats.
    //!
    //! To be used in `[serde(with)]` field attribute.

    use super::*;

    /// Serialize an object representable as bytes using `0x`-prefixed hex encoding
    /// if the target format is human-readable, and plain bytes otherwise.
    pub(crate) fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serialize_with_encoding(obj, serializer, Encoding::Hex)
    }

    /// Deserialize an object representable as bytes assuming `0x`-prefixed hex encoding
    /// if the source format is human-readable, and plain bytes otherwise.
    pub(crate) fn deserialize<'de, T, V, D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: for<'a> TryFromBytes<'a, V>,
        V: fmt::Display,
    {
        deserialize_with_encoding(deserializer, Encoding::Hex)
    }
}

pub(crate) mod as_base64 {
    //! A module containing serialization and deserialization function
    //! that use hex (`0x`-prefixed) representation for bytestrings.
    //!
    //! To be used in `[serde(with)]` field attribute.

    use super::*;

    /// Serialize an object representable as bytes using `base64` encoding
    /// if the target format is human-readable, and plain bytes otherwise.
    pub(crate) fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serialize_with_encoding(obj, serializer, Encoding::Base64)
    }

    /// Deserialize an object representable as bytes assuming `base64` encoding
    /// if the source format is human-readable, and plain bytes otherwise.
    pub(crate) fn deserialize<'de, T, V, D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: for<'a> TryFromBytes<'a, V>,
        V: fmt::Display,
    {
        deserialize_with_encoding(deserializer, Encoding::Base64)
    }
}
