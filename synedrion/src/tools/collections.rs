use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub(crate) struct HoleVecAccum<T> {
    hole_at: usize,
    elems: Vec<Option<T>>,
}

impl<T> HoleVecAccum<T> {
    pub fn new(length: usize, hole_at: usize) -> Self {
        debug_assert!(length > 0 && hole_at < length);
        // We need this to be able to create HoleVec out of HoleVecAccum.
        debug_assert!(<usize as TryInto<u16>>::try_into(length).is_ok());

        // Can't use `vec![]` without requiring `T: Clone`,
        // even though we're only filling it with `None`s.
        let mut elems = Vec::with_capacity(length - 1);
        for _ in 0..(length - 1) {
            elems.push(None);
        }

        Self { hole_at, elems }
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Option<T>> {
        if index == self.hole_at {
            return None;
        }
        let index = if index > self.hole_at {
            index - 1
        } else {
            index
        };
        self.elems.get_mut(index)
    }

    pub fn insert(&mut self, index: usize, value: T) -> Option<()> {
        let slot = self.get_mut(index)?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(value);
        Some(())
    }

    pub fn can_finalize(&self) -> bool {
        self.elems.iter().all(|elem| elem.is_some())
    }

    pub fn is_empty(&self) -> bool {
        self.elems.iter().all(|elem| elem.is_none())
    }

    pub fn finalize(self) -> Result<HoleVec<T>, Self> {
        if self.can_finalize() {
            let elems = self
                .elems
                .into_iter()
                .map(|value| value.unwrap()) // TODO: return Self if there is an error
                .collect();
            Ok(HoleVec {
                hole_at: self.hole_at.try_into().unwrap(),
                elems,
            })
        } else {
            Err(self)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct HoleRange {
    length: usize,
    position: usize,
    hole_at: usize,
}

impl HoleRange {
    pub fn new(length: usize, hole_at: usize) -> Self {
        debug_assert!(length > 0 && hole_at < length);
        Self {
            length,
            hole_at,
            position: 0,
        }
    }

    fn next(&mut self) -> Option<usize> {
        if self.position == self.length {
            None
        } else {
            let to_produce = self.position;
            self.position += 1;
            Some(to_produce)
        }
    }
}

impl Iterator for HoleRange {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next() {
            None => None,
            Some(val) => {
                if val == self.hole_at {
                    self.next()
                } else {
                    Some(val)
                }
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct HoleVec<T> {
    elems: Vec<T>,
    // `u16` because we need it to be serialized uniformly across different platforms,
    // and we don't expect to ever have more than 2^16 shares
    // (which is what this collection is used for).
    hole_at: u16,
}

impl<T> HoleVec<T> {
    pub fn hole_at(&self) -> usize {
        self.hole_at.try_into().unwrap()
    }

    pub fn len(&self) -> usize {
        self.elems.len() + 1
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        if index == self.hole_at() {
            return None;
        }
        let index = if index > self.hole_at() {
            index - 1
        } else {
            index
        };
        self.elems.get(index)
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.elems.iter()
    }

    pub fn enumerate(&self) -> core::iter::Zip<HoleRange, core::slice::Iter<'_, T>> {
        HoleRange::new(self.len(), self.hole_at()).zip(self.elems.iter())
    }

    pub fn into_vec(self, elem: T) -> Vec<T> {
        let hole_at = self.hole_at();
        let mut result = self.elems;
        result.insert(hole_at, elem);
        result
    }

    pub fn map_ref<F, V>(&self, f: F) -> HoleVec<V>
    where
        F: Fn(&T) -> V,
    {
        HoleVec {
            elems: self.elems.iter().map(f).collect(),
            hole_at: self.hole_at,
        }
    }

    pub fn map<F, V>(self, f: F) -> HoleVec<V>
    where
        F: FnMut(T) -> V,
    {
        HoleVec {
            elems: self.elems.into_iter().map(f).collect(),
            hole_at: self.hole_at,
        }
    }

    pub fn map_fallible<F, V, E>(self, f: F) -> Result<HoleVec<V>, E>
    where
        F: FnMut(T) -> Result<V, E>,
    {
        Ok(HoleVec {
            elems: self
                .elems
                .into_iter()
                .map(f)
                .collect::<Result<Vec<_>, E>>()?,
            hole_at: self.hole_at,
        })
    }
}

impl<T, V> HoleVec<(T, V)> {
    pub fn unzip(self) -> (HoleVec<T>, HoleVec<V>) {
        let (elems1, elems2): (Vec<T>, Vec<V>) = self.elems.into_iter().unzip();
        let vec1 = HoleVec {
            hole_at: self.hole_at,
            elems: elems1,
        };
        let vec2 = HoleVec {
            hole_at: self.hole_at,
            elems: elems2,
        };
        (vec1, vec2)
    }
}
