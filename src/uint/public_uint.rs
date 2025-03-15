use alloc::boxed::Box;

use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use serde_encoded_bytes::{Hex, SliceLike};

use super::BoxedEncoding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicUint<T>(T);

impl<T> PublicUint<T> {
    pub fn inner(self) -> T {
        self.0
    }
}

impl<T> Serialize for PublicUint<T>
where
    T: BoxedEncoding,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SliceLike::<Hex>::serialize(&self.0.to_be_bytes(), serializer)
    }
}

impl<'de, T> Deserialize<'de> for PublicUint<T>
where
    T: BoxedEncoding,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Box<[u8]> = SliceLike::<Hex>::deserialize(deserializer)?;
        T::try_from_be_bytes(&bytes).map(Self).map_err(D::Error::custom)
    }
}

impl<T> core::ops::Deref for PublicUint<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> core::ops::DerefMut for PublicUint<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> AsRef<T> for PublicUint<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for PublicUint<T> {
    fn from(source: T) -> Self {
        Self(source)
    }
}
