// TODO(dp): the hashing_serializer crate uses an old version of `digest` (v0.10) which conflicts with our `impl Hashable`, so as a temporary workaround, copy&paste the whole crate source here...
use alloc::{format, string::String};
use core::fmt;

use digest::Update;
use serde::{
    ser::{
        self, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
        SerializeTupleStruct, SerializeTupleVariant,
    },
    Serialize, Serializer,
};

/// A serializer that hashes the data instead of serializing it.
pub struct HashingSerializer<'a, T: Update> {
    /// A reference to the digest that will accumulate the data.
    pub digest: &'a mut T,
}

/// Possible errors during serialization.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error {
    /// The type's [`serde::Serialize`] impl tried to serialize a sequence of undefined length.
    UndefinedSequenceLength,

    /// Sequence length does not fit into `u128`.
    ///
    /// Really, this shouldn't ever happen.
    SequenceLengthTooLarge,

    /// [`Serializer::collect_str`] got called, but heap memory allocation is not available.
    ///
    /// Can only be returned if `alloc` feature not enabled.
    CannotCollectStr,

    /// Custom `serde` error, but memory allocation is not available.
    /// Set a breakpoint where this is thrown for more information.
    ///
    /// Can only be returned if `alloc` feature not enabled).
    #[allow(dead_code)]
    CustomErrorNoAlloc,

    /// Custom `serde` error.
    CustomError(String),
}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::CustomError(format!("{}", msg))
    }
}

impl ser::StdError for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Converts the `usize` sequence length to a fixed length type,
/// since we want the result to be portable.
fn try_into_sequence_length(len: usize) -> Result<u128, Error> {
    u128::try_from(len)
        .ok()
        .ok_or(Error::SequenceLengthTooLarge)
}

impl<'a, T: Update> Serializer for HashingSerializer<'a, T> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&(v as u8).to_be_bytes());
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&v.to_be_bytes());
        Ok(())
    }
    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        // `char` is always at most 4 bytes, regardless of the platform,
        // so this conversion is safe.
        self.digest.update(&u64::from(v).to_be_bytes());
        Ok(())
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.digest.update(v.as_ref());
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.digest.update(v);
        Ok(())
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&[0]);
        Ok(())
    }

    fn serialize_some<V: ?Sized + Serialize>(self, value: &V) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&[1]);
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&variant_index.to_be_bytes());
        Ok(())
    }

    fn serialize_newtype_struct<V: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &V,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<V: ?Sized + Serialize>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        value: &V,
    ) -> Result<Self::Ok, Self::Error> {
        self.digest.update(&variant_index.to_be_bytes());
        value.serialize(self)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        let len = len.ok_or(Error::UndefinedSequenceLength)?;
        self.digest
            .update(&try_into_sequence_length(len)?.to_be_bytes());
        Ok(self)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.digest
            .update(&try_into_sequence_length(len)?.to_be_bytes());
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.digest
            .update(&try_into_sequence_length(len)?.to_be_bytes());
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.digest.update(&variant_index.to_be_bytes());
        self.digest
            .update(&try_into_sequence_length(len)?.to_be_bytes());
        Ok(self)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        let len = len.ok_or(Error::UndefinedSequenceLength)?;
        self.digest
            .update(&try_into_sequence_length(len)?.to_be_bytes());
        Ok(self)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.digest
            .update(&try_into_sequence_length(len)?.to_be_bytes());
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.digest.update(&variant_index.to_be_bytes());
        self.digest
            .update(&try_into_sequence_length(len)?.to_be_bytes());
        Ok(self)
    }

    fn collect_str<V: fmt::Display + ?Sized>(self, _: &V) -> Result<Self::Ok, Self::Error> {
        Err(Error::CannotCollectStr)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

impl<'a, T: Update> SerializeSeq for HashingSerializer<'a, T> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<V: ?Sized + Serialize>(&mut self, value: &V) -> Result<Self::Ok, Error> {
        value.serialize(HashingSerializer {
            digest: self.digest,
        })?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}

impl<'a, T: Update> SerializeTuple for HashingSerializer<'a, T> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<V: ?Sized + Serialize>(&mut self, value: &V) -> Result<Self::Ok, Error> {
        value.serialize(HashingSerializer {
            digest: self.digest,
        })?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}

impl<'a, T: Update> SerializeTupleStruct for HashingSerializer<'a, T> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<V: ?Sized + Serialize>(&mut self, value: &V) -> Result<Self::Ok, Error> {
        value.serialize(HashingSerializer {
            digest: self.digest,
        })?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}

impl<'a, T: Update> SerializeTupleVariant for HashingSerializer<'a, T> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<V: ?Sized + Serialize>(&mut self, value: &V) -> Result<Self::Ok, Error> {
        value.serialize(HashingSerializer {
            digest: self.digest,
        })?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}

impl<'a, T: Update> SerializeMap for HashingSerializer<'a, T> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<K: ?Sized + Serialize>(&mut self, key: &K) -> Result<Self::Ok, Error> {
        key.serialize(HashingSerializer {
            digest: self.digest,
        })?;
        Ok(())
    }

    fn serialize_value<V: ?Sized + Serialize>(&mut self, value: &V) -> Result<Self::Ok, Error> {
        value.serialize(HashingSerializer {
            digest: self.digest,
        })?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}

impl<'a, T: Update> SerializeStruct for HashingSerializer<'a, T> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<V: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        value: &V,
    ) -> Result<Self::Ok, Error> {
        value.serialize(HashingSerializer {
            digest: self.digest,
        })?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}

impl<'a, T: Update> SerializeStructVariant for HashingSerializer<'a, T> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<V: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        value: &V,
    ) -> Result<Self::Ok, Error> {
        value.serialize(HashingSerializer {
            digest: self.digest,
        })?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use digest::Digest;
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use serde::Serialize;
    use sha2::Sha256;

    use super::HashingSerializer;

    #[test]
    fn hash_serializable() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();

        let mut digest = Sha256::new();
        let serializer = HashingSerializer {
            digest: &mut digest,
        };
        vk.serialize(serializer).unwrap();
    }
}
