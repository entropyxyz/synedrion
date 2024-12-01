use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) struct HideDebug<T>(T);

impl<T> Debug for HideDebug<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("<secret>").finish()
    }
}

impl<T> From<T> for HideDebug<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for HideDebug<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for HideDebug<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
