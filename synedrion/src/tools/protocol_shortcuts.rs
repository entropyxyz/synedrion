use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
};
use core::fmt::Debug;

use manul::protocol::{
    Artifact, Deserializer, EchoBroadcast, LocalError, Payload, ProtocolMessagePart, ProtocolValidationError, RoundId,
};
use serde::Deserialize;

pub(crate) trait Without {
    type Item;
    fn without(self, item: &Self::Item) -> Self;
}

impl<T: Ord> Without for BTreeSet<T> {
    type Item = T;
    fn without(self, item: &Self::Item) -> Self {
        let mut set = self;
        set.remove(item);
        set
    }
}

pub(crate) trait MapValues<K, V> {
    fn map_values<F, T>(self, f: F) -> BTreeMap<K, T>
    where
        F: Fn(V) -> T;

    fn map_values_ref<F, T>(&self, f: F) -> BTreeMap<K, T>
    where
        K: Clone,
        F: Fn(&V) -> T;
}

impl<K: Ord, V> MapValues<K, V> for BTreeMap<K, V> {
    fn map_values<F, T>(self, f: F) -> BTreeMap<K, T>
    where
        F: Fn(V) -> T,
    {
        self.into_iter().map(|(key, value)| (key, f(value))).collect()
    }

    fn map_values_ref<F, T>(&self, f: F) -> BTreeMap<K, T>
    where
        K: Clone,
        F: Fn(&V) -> T,
    {
        self.iter().map(|(key, value)| (key.clone(), f(value))).collect()
    }
}

pub(crate) trait DowncastMap {
    type Key;
    fn downcast_all<T: 'static>(self) -> Result<BTreeMap<Self::Key, T>, LocalError>;
}

impl<K: Ord> DowncastMap for BTreeMap<K, Payload> {
    type Key = K;
    fn downcast_all<T: 'static>(self) -> Result<BTreeMap<K, T>, LocalError> {
        self.into_iter()
            .map(|(k, payload)| payload.try_to_typed::<T>().map(|v| (k, v)))
            .collect::<Result<_, _>>()
    }
}

impl<K: Ord> DowncastMap for BTreeMap<K, Artifact> {
    type Key = K;
    fn downcast_all<T: 'static>(self) -> Result<BTreeMap<K, T>, LocalError> {
        self.into_iter()
            .map(|(k, artifact)| artifact.try_to_typed::<T>().map(|v| (k, v)))
            .collect::<Result<_, _>>()
    }
}

pub(crate) trait SafeGet<K, V> {
    fn safe_get(&self, container: &str, key: &K) -> Result<&V, LocalError>;
    fn try_get(&self, container: &str, key: &K) -> Result<&V, ProtocolValidationError>;
}

impl<K: Ord + Debug, V> SafeGet<K, V> for BTreeMap<K, V> {
    fn safe_get(&self, container: &str, key: &K) -> Result<&V, LocalError> {
        self.get(key)
            .ok_or_else(|| LocalError::new(format!("Key {key:?} not found in {container}")))
    }

    fn try_get(&self, container: &str, key: &K) -> Result<&V, ProtocolValidationError> {
        self.get(key)
            .ok_or_else(|| ProtocolValidationError::InvalidEvidence(format!("Key {key:?} not found in {container}")))
    }
}

pub(crate) trait GetRound<V> {
    fn get_round(&self, round_id: u8) -> Result<&V, ProtocolValidationError>;
}

impl<V> GetRound<V> for BTreeMap<RoundId, V> {
    fn get_round(&self, round_id: u8) -> Result<&V, ProtocolValidationError> {
        self.get(&RoundId::new(round_id)).ok_or_else(|| {
            ProtocolValidationError::InvalidEvidence(format!("Entry for round {round_id} is not present"))
        })
    }
}

pub(crate) trait DeserializeAll<Id> {
    fn deserialize_all<T: for<'de> Deserialize<'de>>(
        &self,
        deserializer: &Deserializer,
    ) -> Result<BTreeMap<Id, T>, ProtocolValidationError>;
}

impl<Id: Clone + Ord> DeserializeAll<Id> for BTreeMap<Id, EchoBroadcast> {
    fn deserialize_all<T: for<'de> Deserialize<'de>>(
        &self,
        deserializer: &Deserializer,
    ) -> Result<BTreeMap<Id, T>, ProtocolValidationError> {
        let deserialized = self
            .iter()
            .map(|(id, echo)| {
                echo.deserialize::<T>(deserializer)
                    .map(|deserialized| (id.clone(), deserialized))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(deserialized)
    }
}

pub(crate) fn verify_that(condition: bool) -> Result<(), ProtocolValidationError> {
    if condition {
        Ok(())
    } else {
        Err(ProtocolValidationError::InvalidEvidence(
            "the reported error cannot be reproduced".into(),
        ))
    }
}
