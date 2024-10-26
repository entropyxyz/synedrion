use alloc::collections::{BTreeMap, BTreeSet};

pub(crate) mod bitvec;
pub(crate) mod hashing;
mod hide_debug;
pub(crate) mod sss;

pub(crate) use hide_debug::HideDebug;

use manul::protocol::{Artifact, LocalError, Payload};

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
