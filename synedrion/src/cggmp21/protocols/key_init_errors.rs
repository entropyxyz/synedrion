use alloc::collections::{BTreeMap, BTreeSet};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::key_init::{Round1Message, Round2Message, Round3Message};
use crate::cggmp21::SchemeParams;
use crate::rounds::EvidenceRequiresMessages;
use crate::sessions::Message;
use crate::tools::{
    bitvec::BitVec,
    hashing::{Chain, FofHasher},
};

/// Possible verifiable errors of the KeyGen protocol.
#[derive(Debug, Clone, Copy)]
pub struct KeyInitError<P: SchemeParams, I> {
    pub(crate) error: KeyInitErrorType,
    pub(crate) phantom: (PhantomData<P>, PhantomData<I>),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum KeyInitErrorType {
    /// A hash mismatch in Round 2.
    R2HashMismatch,
    /// Failed to verify `П^{sch}` in Round 3.
    R3InvalidSchProof,
}

impl<P: SchemeParams, I: Ord + Clone + Serialize + for<'de> Deserialize<'de>>
    EvidenceRequiresMessages<I> for KeyInitError<P, I>
{
    fn requires_messages(&self) -> &[(u8, bool)] {
        match self.error {
            KeyInitErrorType::R2HashMismatch => &[(1, false), (2, false)],
            KeyInitErrorType::R3InvalidSchProof => &[(2, true), (3, false)],
        }
    }

    fn verify_malicious(
        &self,
        shared_randomness: &[u8],
        other_ids: &BTreeSet<I>,
        my_id: &I,
        messages: &BTreeMap<(u8, bool), Message>,
    ) -> bool {
        match self.error {
            KeyInitErrorType::R2HashMismatch => {
                let r1 = messages[&(1, false)].to_typed().unwrap();
                let r2 = messages[&(2, false)].to_typed().unwrap();
                self.verify_r2_hash_mismatch(shared_randomness, other_ids, my_id, &r1, &r2)
            }
            KeyInitErrorType::R3InvalidSchProof => {
                let r2 = messages[&(2, true)].to_typed_echo().unwrap();
                let r3 = messages[&(3, false)].to_typed().unwrap();
                self.verify_r3_invalid_sch_proof(shared_randomness, other_ids, my_id, &r2, &r3)
            }
        }
    }
}

impl<P: SchemeParams, I: Ord + Clone + Serialize + for<'de> Deserialize<'de>> KeyInitError<P, I> {
    pub fn verify_r2_hash_mismatch(
        &self,
        shared_randomness: &[u8],
        other_ids: &BTreeSet<I>,
        my_id: &I,
        r1_bcast: &Round1Message,
        r2_bcast: &Round2Message<P>,
    ) -> bool {
        let mut all_ids = other_ids.clone();
        all_ids.insert(my_id.clone());
        let sid_hash = FofHasher::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&all_ids)
            .finalize();
        let r1_hash = r1_bcast.cap_v;
        let r2_hash = r2_bcast.data.hash(&sid_hash, my_id);
        r1_hash != r2_hash
    }

    pub fn verify_r3_invalid_sch_proof(
        &self,
        shared_randomness: &[u8],
        other_ids: &BTreeSet<I>,
        my_id: &I,
        r2_bcasts: &BTreeMap<I, Round2Message<P>>,
        r3_bcast: &Round3Message,
    ) -> bool {
        let mut all_ids = other_ids.clone();
        all_ids.insert(my_id.clone());
        let sid_hash = FofHasher::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&all_ids)
            .finalize();
        let rid = BitVec::xor_all(r2_bcasts.values().map(|bcast| &bcast.data.rid));
        let data = &r2_bcasts[my_id].data;
        let aux = (&sid_hash, my_id, &rid);
        if !r3_bcast.psi.verify(&data.cap_a, &data.cap_x, &aux) {
            return false;
        }
        true
    }
}
