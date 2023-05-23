use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub(crate) struct HoleVecAccum<T: Clone> {
    hole_at: usize,
    elems: Vec<Option<T>>,
}

impl<T: Clone> HoleVecAccum<T> {
    pub fn new(length: usize, hole_at: usize) -> Self {
        debug_assert!(length > 0 && hole_at < length);
        Self {
            hole_at,
            elems: vec![None; length - 1],
        }
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

    pub fn finalize(self) -> Result<HoleVec<T>, Self> {
        if self.can_finalize() {
            let elems = self
                .elems
                .into_iter()
                .map(|value| value.unwrap()) // TODO: return Self if there is an error
                .collect();
            Ok(HoleVec {
                hole_at: self.hole_at,
                elems,
            })
        } else {
            Err(self)
        }
    }
}

#[derive(Copy, Clone, Debug)]
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

// TODO: how will serializing usize work on 32-bit platforms?
// actually, why do we even need to serialize this?
#[derive(Serialize, Deserialize)]
pub(crate) struct HoleVec<T> {
    elems: Vec<T>,
    hole_at: usize,
}

impl<T> HoleVec<T> {
    pub fn hole_at(&self) -> usize {
        self.hole_at
    }

    pub fn len(&self) -> usize {
        self.elems.len() + 1
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        if index == self.hole_at {
            return None;
        }
        let index = if index > self.hole_at {
            index - 1
        } else {
            index
        };
        self.elems.get(index)
    }

    pub fn range(&self) -> HoleRange {
        HoleRange::new(self.len(), self.hole_at())
    }

    pub fn iter(&self) -> core::slice::Iter<T> {
        self.elems.iter()
    }

    pub fn enumerate(&self) -> core::iter::Zip<HoleRange, core::slice::Iter<'_, T>> {
        HoleRange::new(self.len(), self.hole_at()).zip(self.elems.iter())
    }

    pub fn into_vec(self, elem: T) -> Vec<T> {
        let mut result = self.elems;
        result.insert(self.hole_at, elem);
        result
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
}

impl<T: Clone> Clone for HoleVec<T> {
    fn clone(&self) -> Self {
        Self {
            hole_at: self.hole_at,
            elems: self.elems.clone(),
        }
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
