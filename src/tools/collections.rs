use alloc::collections::BTreeMap;

#[derive(Clone)]
pub(crate) struct HoleMap<K: Ord, T: Clone>(BTreeMap<K, Option<T>>);

impl<K: Ord + Clone, T: Clone> HoleMap<K, T> {
    pub fn new(keys: impl IntoIterator<Item = K>) -> Self {
        Self(keys.into_iter().map(|key| (key, None)).collect())
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut Option<T>> {
        self.0.get_mut(key)
    }

    pub fn keys(&self) -> alloc::collections::btree_map::Keys<'_, K, Option<T>> {
        self.0.keys()
    }

    pub fn can_finalize(&self) -> bool {
        self.0.values().all(|elem| elem.is_some())
    }

    pub fn try_finalize(self) -> Result<BTreeMap<K, T>, Self> {
        if self.can_finalize() {
            Ok(self
                .0
                .into_iter()
                .map(|(key, value)| (key, value.unwrap())) // TODO: return Self if there is an error
                .collect::<BTreeMap<_, _>>())
        } else {
            Err(self)
        }
    }
}
