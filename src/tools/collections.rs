use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::tools::hashing::{Chain, Hashable};

// TODO: should it be here? HoleVecs can just function with usizes I think.
// Maybe it's better moved to `protocols/common`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PartyIdx(u32);

impl PartyIdx {
    pub fn as_usize(self) -> usize {
        self.0.try_into().unwrap()
    }

    pub fn from_usize(val: usize) -> Self {
        Self(val.try_into().unwrap())
    }

    fn inc(self) -> Self {
        Self(self.0 + 1)
    }

    fn dec(self) -> Self {
        Self(self.0 - 1)
    }
}

impl Hashable for PartyIdx {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HoleVecAccum<T: Clone> {
    hole_at: PartyIdx,
    elems: Vec<Option<T>>,
}

impl<T: Clone> HoleVecAccum<T> {
    pub fn new(length: usize, hole_at: PartyIdx) -> Self {
        debug_assert!(length > 0 && hole_at.0 < length as u32);
        Self {
            hole_at,
            elems: vec![None; length - 1],
        }
    }

    pub fn get_mut(&mut self, index: PartyIdx) -> Option<&mut Option<T>> {
        if index == self.hole_at {
            return None;
        }
        let index = if index > self.hole_at {
            index.dec()
        } else {
            index
        };
        self.elems.get_mut(index.as_usize())
    }

    pub fn insert(&mut self, index: PartyIdx, value: T) -> Option<()> {
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
                .collect::<Vec<_>>();
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
    position: PartyIdx,
    hole_at: PartyIdx,
}

impl HoleRange {
    pub fn new(length: usize, hole_at: PartyIdx) -> Self {
        debug_assert!(length > 0 && hole_at.as_usize() < length);
        Self {
            length,
            hole_at,
            position: PartyIdx(0),
        }
    }

    fn next(&mut self) -> Option<PartyIdx> {
        if self.position.as_usize() == self.length {
            None
        } else {
            let to_produce = self.position;
            self.position = self.position.inc();
            Some(to_produce)
        }
    }
}

impl Iterator for HoleRange {
    type Item = PartyIdx;

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

#[derive(Serialize, Deserialize)]
pub(crate) struct HoleVec<T> {
    elems: Vec<T>,
    hole_at: PartyIdx,
}

impl<T> HoleVec<T> {
    pub fn hole_at(&self) -> PartyIdx {
        self.hole_at
    }

    pub fn len(&self) -> usize {
        self.elems.len() + 1
    }

    pub fn get(&self, index: PartyIdx) -> Option<&T> {
        if index == self.hole_at {
            return None;
        }
        let index = if index > self.hole_at {
            index.dec()
        } else {
            index
        };
        self.elems.get(index.as_usize())
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
        result.insert(self.hole_at.as_usize(), elem);
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
