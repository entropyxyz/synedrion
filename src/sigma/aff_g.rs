use core::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::paillier::PaillierParams;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AffGProof<P: PaillierParams>(PhantomData<P>);

impl<P: PaillierParams> AffGProof<P> {
    pub fn random(_rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(PhantomData)
    }

    pub fn verify(&self) -> bool {
        true
    }
}
