pub(crate) struct HoleVec<T: Clone>(Vec<Option<T>>);

pub(crate) enum OnInsert {
    Ok,
    AlreadyExists,
    OutOfBounds,
}

impl<T: Clone> HoleVec<T> {
    pub fn new(size: usize) -> Self {
        Self(vec![None; size])
    }

    pub fn try_insert(&mut self, index: usize, element: T) -> OnInsert {
        if index >= self.0.len() {
            OnInsert::OutOfBounds
        } else if self.0[index].is_none() {
            self.0[index] = Some(element);
            OnInsert::Ok
        } else {
            OnInsert::AlreadyExists
        }
    }

    pub fn try_finalize(self) -> Result<Vec<T>, Self> {
        if self.0.iter().all(|elem| elem.is_some()) {
            Ok(self
                .0
                .into_iter()
                .map(|elem| elem.unwrap())
                .collect::<Vec<_>>())
        } else {
            Err(self)
        }
    }
}

impl<T: Clone + core::fmt::Debug> core::fmt::Debug for HoleVec<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_tuple("HoleVec").field(&self.0).finish()
    }
}
