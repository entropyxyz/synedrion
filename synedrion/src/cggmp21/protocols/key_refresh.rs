//! KeyRefresh protocol, in the paper Auxiliary Info. & Key Refresh in Three Rounds (Fig. 6).
//! This protocol generates an update to the secret key shares and new auxiliary parameters
//! for ZK proofs (e.g. Paillier keys).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};

use super::super::{
    sigma::{FacProof, ModProof, PrmProof, SchCommitment, SchProof, SchSecret},
    AuxInfo, KeyShareChange, PublicAuxInfo, SchemeParams, SecretAuxInfo,
};
use crate::curve::{Point, Scalar};
use crate::paillier::{
    Ciphertext, CiphertextMod, PublicKeyPaillier, PublicKeyPaillierPrecomputed, RPParams,
    RPParamsMod, RPSecret, Randomizer, SecretKeyPaillier, SecretKeyPaillierPrecomputed,
};
use crate::rounds::{
    no_broadcast_messages, no_direct_messages, FinalizableToNextRound, FinalizableToResult,
    FinalizeError, FirstRound, InitError, ProtocolResult, Round, ToNextRound, ToResult,
};
use crate::tools::bitvec::BitVec;
use crate::tools::hashing::{Chain, FofHasher, HashOutput};
use crypto_bigint::BitOps;

/// Possible results of the KeyRefresh protocol.
#[derive(Debug)]
pub struct KeyRefreshResult<P: SchemeParams, I: Debug>(PhantomData<P>, PhantomData<I>);

impl<P: SchemeParams, I: Debug + Ord> ProtocolResult for KeyRefreshResult<P, I> {
    type Success = (KeyShareChange<P, I>, AuxInfo<P, I>);
    type ProvableError = KeyRefreshError<P>;
    type CorrectnessProof = ();
}

#[derive(Debug)]
pub struct KeyRefreshError<P: SchemeParams>(KeyRefreshErrorEnum<P>);

#[derive(Debug)]
enum KeyRefreshErrorEnum<P: SchemeParams> {
    // TODO (#43): this can be removed when error verification is added
    #[allow(dead_code)]
    Round2(String),
    // TODO (#43): this can be removed when error verification is added
    #[allow(dead_code)]
    Round3(String),
    // TODO (#43): this can be removed when error verification is added
    #[allow(dead_code)]
    Round3MismatchedSecret {
        cap_c: Ciphertext<P::Paillier>,
        x: Scalar,
        mu: Randomizer<P::Paillier>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
        PrmProof<P>: Serialize,
    "))]
#[serde(bound(deserialize = "
        PrmProof<P>: for<'x> Deserialize<'x>,
    "))]
pub struct PublicData1<P: SchemeParams> {
    cap_x_to_send: Vec<Point>, // $X_i^j$ where $i$ is this party's index
    cap_a_to_send: Vec<SchCommitment>, // $A_i^j$ where $i$ is this party's index
    cap_y: Point,
    cap_b: SchCommitment,
    paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    rp_params: RPParams<P::Paillier>,            // $s_i$ and $t_i$
    hat_psi: PrmProof<P>,
    rho: BitVec,
    u: BitVec,
}

#[derive(Debug, Clone)]
pub struct PublicData1Precomp<P: SchemeParams> {
    data: PublicData1<P>,
    paillier_pk: PublicKeyPaillierPrecomputed<P::Paillier>,
    rp_params: RPParamsMod<P::Paillier>,
}

struct Context<P: SchemeParams, I> {
    paillier_sk: SecretKeyPaillierPrecomputed<P::Paillier>,
    y: Scalar,
    x_to_send: BTreeMap<I, Scalar>, // $x_i^j$ where $i$ is this party's index
    tau_y: SchSecret,
    tau_x: BTreeMap<I, SchSecret>,
    data_precomp: PublicData1Precomp<P>,
    my_id: I,
    other_ids: BTreeSet<I>,
    sid_hash: HashOutput,
    ids_ordering: BTreeMap<I, usize>,
}

impl<P: SchemeParams> PublicData1<P> {
    fn hash<I: Serialize>(&self, sid_hash: &HashOutput, id: &I) -> HashOutput {
        FofHasher::new_with_dst(b"Auxiliary")
            .chain(sid_hash)
            .chain(id)
            .chain(self)
            .finalize()
    }
}

pub struct Round1<P: SchemeParams, I> {
    context: Context<P, I>,
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FirstRound<I> for Round1<P, I> {
    type Inputs = ();
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        other_ids: BTreeSet<I>,
        my_id: I,
        _inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let mut all_ids = other_ids.clone();
        all_ids.insert(my_id.clone());

        let ids_ordering = all_ids
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, id)| (id, idx))
            .collect();

        let sid_hash = FofHasher::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&all_ids)
            .finalize();

        // $p_i$, $q_i$
        let paillier_sk = SecretKeyPaillier::<P::Paillier>::random(rng).to_precomputed();
        // $N_i$
        let paillier_pk = paillier_sk.public_key();

        // El-Gamal key
        let y = Scalar::random(rng);
        let cap_y = y.mul_by_generator();

        // The secret and the commitment for the Schnorr PoK of the El-Gamal key
        let tau_y = SchSecret::random(rng); // $\tau$
        let cap_b = SchCommitment::new(&tau_y);

        // Secret share updates for each node ($x_i^j$ where $i$ is this party's index).
        let x_to_send = all_ids
            .iter()
            .cloned()
            .zip(Scalar::ZERO.split(rng, all_ids.len()))
            .collect::<BTreeMap<_, _>>();

        // Public counterparts of secret share updates ($X_i^j$ where $i$ is this party's index).
        let cap_x_to_send = x_to_send.values().map(|x| x.mul_by_generator()).collect();

        let lambda = RPSecret::random(rng, &paillier_sk);
        // Ring-Pedersen parameters ($s$, $t$) bundled in a single object.
        let rp_params = RPParamsMod::random_with_secret(rng, &lambda, paillier_pk);

        let aux = (&sid_hash, &my_id);
        let hat_psi = PrmProof::<P>::new(rng, &paillier_sk, &lambda, &rp_params, &aux);

        // The secrets share changes ($\tau_j$, not to be confused with $\tau$)
        let tau_x = all_ids
            .iter()
            .map(|id| (id.clone(), SchSecret::random(rng)))
            .collect::<BTreeMap<_, _>>();

        // The commitments for share changes ($A_i^j$ where $i$ is this party's index)
        let cap_a_to_send = tau_x.values().map(SchCommitment::new).collect();

        let rho = BitVec::random(rng, P::SECURITY_PARAMETER);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        let data = PublicData1 {
            cap_x_to_send,
            cap_a_to_send,
            cap_y,
            cap_b,
            paillier_pk: paillier_pk.to_minimal(),
            rp_params: rp_params.retrieve(),
            hat_psi,
            rho,
            u,
        };

        let data_precomp = PublicData1Precomp {
            data,
            paillier_pk: paillier_pk.clone(),
            rp_params,
        };

        let context = Context {
            paillier_sk,
            y,
            x_to_send,
            tau_x,
            tau_y,
            data_precomp,
            my_id,
            other_ids,
            sid_hash,
            ids_ordering,
        };

        Ok(Self { context })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1Message {
    cap_v: HashOutput,
}

pub struct Round1Payload {
    cap_v: HashOutput,
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> Round<I> for Round1<P, I> {
    type Type = ToNextRound;
    type Result = KeyRefreshResult<P, I>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn my_id(&self) -> &I {
        &self.context.my_id
    }

    const REQUIRES_ECHO: bool = true;
    type BroadcastMessage = Round1Message;
    type DirectMessage = ();
    type Payload = Round1Payload;
    type Artifact = ();

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        Some(Round1Message {
            cap_v: self
                .context
                .data_precomp
                .data
                .hash(&self.context.sid_hash, self.my_id()),
        })
    }

    no_direct_messages!(I);

    fn verify_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        _from: &I,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        Ok(Round1Payload {
            cap_v: broadcast_msg.cap_v,
        })
    }
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FinalizableToNextRound<I>
    for Round1<P, I>
{
    type NextRound = Round2<P, I>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let others_cap_v = payloads
            .into_iter()
            .map(|(id, payload)| (id, payload.cap_v))
            .collect();
        Ok(Round2 {
            context: self.context,
            others_cap_v,
        })
    }
}

pub struct Round2<P: SchemeParams, I> {
    context: Context<P, I>,
    others_cap_v: BTreeMap<I, HashOutput>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicData1<P>: Serialize"))]
#[serde(bound(deserialize = "PublicData1<P>: for<'x> Deserialize<'x>"))]
pub struct Round2Message<P: SchemeParams> {
    data: PublicData1<P>,
}

pub struct Round2Payload<P: SchemeParams> {
    data: PublicData1Precomp<P>,
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> Round<I> for Round2<P, I> {
    type Type = ToNextRound;
    type Result = KeyRefreshResult<P, I>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn my_id(&self) -> &I {
        &self.context.my_id
    }

    type BroadcastMessage = Round2Message<P>;
    type DirectMessage = ();
    type Payload = Round2Payload<P>;
    type Artifact = ();

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        Some(Round2Message {
            data: self.context.data_precomp.data.clone(),
        })
    }

    no_direct_messages!(I);

    fn verify_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        if &broadcast_msg.data.hash(&self.context.sid_hash, from)
            != self.others_cap_v.get(from).unwrap()
        {
            return Err(KeyRefreshError(KeyRefreshErrorEnum::Round2(
                "Hash mismatch".into(),
            )));
        }

        let paillier_pk = broadcast_msg.data.paillier_pk.to_precomputed();

        if (paillier_pk.modulus().bits_vartime() as usize) < 8 * P::SECURITY_PARAMETER {
            return Err(KeyRefreshError(KeyRefreshErrorEnum::Round2(
                "Paillier modulus is too small".into(),
            )));
        }

        if broadcast_msg.data.cap_x_to_send.iter().sum::<Point>() != Point::IDENTITY {
            return Err(KeyRefreshError(KeyRefreshErrorEnum::Round2(
                "Sum of X points is not identity".into(),
            )));
        }

        let aux = (&self.context.sid_hash, &from);

        let rp_params = broadcast_msg.data.rp_params.to_mod(&paillier_pk);
        if !broadcast_msg.data.hat_psi.verify(&rp_params, &aux) {
            return Err(KeyRefreshError(KeyRefreshErrorEnum::Round2(
                "PRM verification failed".into(),
            )));
        }

        Ok(Round2Payload {
            data: PublicData1Precomp {
                data: broadcast_msg.data,
                paillier_pk,
                rp_params,
            },
        })
    }
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FinalizableToNextRound<I>
    for Round2<P, I>
{
    type NextRound = Round3<P, I>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let others_data = payloads
            .into_iter()
            .map(|(id, payload)| (id, payload.data))
            .collect::<BTreeMap<_, _>>();
        let mut rho = self.context.data_precomp.data.rho.clone();
        for data in others_data.values() {
            rho ^= &data.data.rho;
        }

        Ok(Round3::new(rng, self.context, others_data, rho))
    }
}

pub struct Round3<P: SchemeParams, I> {
    context: Context<P, I>,
    rho: BitVec,
    others_data: BTreeMap<I, PublicData1Precomp<P>>,
    psi_mod: ModProof<P>,
    pi: SchProof,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    ModProof<P>: Serialize,
    FacProof<P>: Serialize,
    Ciphertext<P::Paillier>: Serialize,
"))]
#[serde(bound(deserialize = "
    ModProof<P>: for<'x> Deserialize<'x>,
    FacProof<P>: for<'x> Deserialize<'x>,
    Ciphertext<P::Paillier>: for<'x> Deserialize<'x>,
"))]
pub struct PublicData2<P: SchemeParams> {
    psi_mod: ModProof<P>, // $\psi_i$, a P^{mod} for the Paillier modulus
    phi: FacProof<P>,
    pi: SchProof,
    paillier_enc_x: Ciphertext<P::Paillier>, // `C_j,i`
    psi_sch: SchProof,                       // $psi_i^j$, a P^{sch} for the secret share change
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> Round3<P, I> {
    fn new(
        rng: &mut impl CryptoRngCore,
        context: Context<P, I>,
        others_data: BTreeMap<I, PublicData1Precomp<P>>,
        rho: BitVec,
    ) -> Self {
        let aux = (&context.sid_hash, &context.my_id, &rho);
        let psi_mod = ModProof::new(rng, &context.paillier_sk, &aux);

        let pi = SchProof::new(
            &context.tau_y,
            &context.y,
            &context.data_precomp.data.cap_b,
            &context.data_precomp.data.cap_y,
            &aux,
        );

        Self {
            context,
            others_data,
            rho,
            psi_mod,
            pi,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicData2<P>: Serialize"))]
#[serde(bound(deserialize = "PublicData2<P>: for<'x> Deserialize<'x>"))]
pub struct Round3Message<P: SchemeParams> {
    data2: PublicData2<P>,
}

pub struct Round3Payload {
    x: Scalar, // $x_j^i$, a secret share change received from the party $j$
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> Round<I> for Round3<P, I> {
    type Type = ToResult;
    type Result = KeyRefreshResult<P, I>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn my_id(&self) -> &I {
        &self.context.my_id
    }

    type BroadcastMessage = ();
    type DirectMessage = Round3Message<P>;
    type Payload = Round3Payload;
    type Artifact = ();

    no_broadcast_messages!();

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &I,
    ) -> (Self::DirectMessage, Self::Artifact) {
        let aux = (&self.context.sid_hash, self.my_id(), &self.rho);

        let data = self.others_data.get(destination).unwrap();

        let phi = FacProof::new(
            rng,
            &self.context.paillier_sk,
            &self.others_data.get(destination).unwrap().rp_params,
            &aux,
        );

        let destination_idx = self.context.ids_ordering[destination];

        let x_secret = self.context.x_to_send[destination];
        let x_public = self.context.data_precomp.data.cap_x_to_send[destination_idx];
        let ciphertext =
            CiphertextMod::new(rng, &data.paillier_pk, &P::uint_from_scalar(&x_secret));

        let psi_sch = SchProof::new(
            &self.context.tau_x[destination],
            &x_secret,
            &self.context.data_precomp.data.cap_a_to_send[destination_idx],
            &x_public,
            &aux,
        );

        let data2 = PublicData2 {
            psi_mod: self.psi_mod.clone(),
            phi,
            pi: self.pi.clone(),
            paillier_enc_x: ciphertext.retrieve(),
            psi_sch,
        };

        (Round3Message { data2 }, ())
    }

    fn verify_message(
        &self,
        rng: &mut impl CryptoRngCore,
        from: &I,
        _broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let sender_data = &self.others_data.get(from).unwrap();

        let enc_x = direct_msg
            .data2
            .paillier_enc_x
            .to_mod(self.context.paillier_sk.public_key());

        let x = P::scalar_from_uint(&enc_x.decrypt(&self.context.paillier_sk));

        let my_idx = self.context.ids_ordering[self.my_id()];

        if x.mul_by_generator() != sender_data.data.cap_x_to_send[my_idx] {
            let mu = enc_x.derive_randomizer(&self.context.paillier_sk);
            return Err(KeyRefreshError(
                KeyRefreshErrorEnum::Round3MismatchedSecret {
                    cap_c: direct_msg.data2.paillier_enc_x,
                    x,
                    mu: mu.retrieve(),
                },
            ));
        }

        let aux = (&self.context.sid_hash, &from, &self.rho);

        if !direct_msg
            .data2
            .psi_mod
            .verify(rng, &sender_data.paillier_pk, &aux)
        {
            return Err(KeyRefreshError(KeyRefreshErrorEnum::Round3(
                "Mod proof verification failed".into(),
            )));
        }

        if !direct_msg.data2.phi.verify(
            &sender_data.paillier_pk,
            &self.context.data_precomp.rp_params,
            &aux,
        ) {
            return Err(KeyRefreshError(KeyRefreshErrorEnum::Round3(
                "Fac proof verification failed".into(),
            )));
        }

        if !direct_msg
            .data2
            .pi
            .verify(&sender_data.data.cap_b, &sender_data.data.cap_y, &aux)
        {
            return Err(KeyRefreshError(KeyRefreshErrorEnum::Round3(
                "Sch proof verification (Y) failed".into(),
            )));
        }

        if !direct_msg.data2.psi_sch.verify(
            &sender_data.data.cap_a_to_send[my_idx],
            &sender_data.data.cap_x_to_send[my_idx],
            &aux,
        ) {
            return Err(KeyRefreshError(KeyRefreshErrorEnum::Round3(
                "Sch proof verification (X) failed".into(),
            )));
        }

        Ok(Round3Payload { x })
    }
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FinalizableToResult<I> for Round3<P, I> {
    fn finalize_to_result(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let others_x = payloads
            .into_iter()
            .map(|(id, payload)| (id, payload.x))
            .collect::<BTreeMap<_, _>>();

        // The combined secret share change
        let x_star = others_x.values().sum::<Scalar>() + self.context.x_to_send[self.my_id()];

        let my_id = self.context.my_id.clone();
        let mut all_ids = self.context.other_ids;
        all_ids.insert(self.context.my_id);

        let mut all_data = self.others_data;
        all_data.insert(my_id.clone(), self.context.data_precomp);

        // The combined public share changes for each node
        let cap_x_star = all_ids
            .iter()
            .enumerate()
            .map(|(idx, id)| {
                (
                    id.clone(),
                    all_data
                        .values()
                        .map(|data| data.data.cap_x_to_send[idx])
                        .sum(),
                )
            })
            .collect();

        let public_aux = all_data
            .into_iter()
            .map(|(id, data)| {
                (
                    id,
                    PublicAuxInfo {
                        el_gamal_pk: data.data.cap_y,
                        paillier_pk: data.paillier_pk.to_minimal(),
                        rp_params: data.rp_params.retrieve(),
                    },
                )
            })
            .collect();

        let secret_aux = SecretAuxInfo {
            paillier_sk: self.context.paillier_sk.to_minimal(),
            el_gamal_sk: SecretBox::new(Box::new(self.context.y)),
        };

        let key_share_change = KeyShareChange {
            owner: my_id.clone(),
            secret_share_change: SecretBox::new(Box::new(x_star)),
            public_share_changes: cap_x_star,
            phantom: PhantomData,
        };

        let aux_info = AuxInfo {
            owner: my_id.clone(),
            secret_aux,
            public_aux,
        };

        Ok((key_share_change, aux_info))
    }
}

#[cfg(test)]
mod tests {

    use alloc::collections::{BTreeMap, BTreeSet};

    use rand_core::{OsRng, RngCore};
    use secrecy::ExposeSecret;

    use super::Round1;
    use crate::cggmp21::TestParams;
    use crate::curve::Scalar;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round, Id, Without},
        FirstRound,
    };

    #[test]
    fn execute_key_refresh() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let ids = BTreeSet::from([Id(0), Id(1), Id(2)]);

        let r1 = ids
            .iter()
            .map(|id| {
                let round = Round1::<TestParams, Id>::new(
                    &mut OsRng,
                    &shared_randomness,
                    ids.clone().without(id),
                    *id,
                    (),
                )
                .unwrap();
                (*id, round)
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let results = step_result(&mut OsRng, r3a).unwrap();

        let (changes, aux_infos): (BTreeMap<_, _>, BTreeMap<_, _>) = results
            .into_iter()
            .map(|(id, (change, aux))| ((id, change), (id, aux)))
            .unzip();

        // Check that public points correspond to secret scalars
        for (id, change) in changes.iter() {
            for other_change in changes.values() {
                assert_eq!(
                    change
                        .secret_share_change
                        .expose_secret()
                        .mul_by_generator(),
                    other_change.public_share_changes[id]
                );
            }
        }

        for (id, aux_info) in aux_infos.iter() {
            for other_aux_info in aux_infos.values() {
                assert_eq!(
                    aux_info
                        .secret_aux
                        .el_gamal_sk
                        .expose_secret()
                        .mul_by_generator(),
                    other_aux_info.public_aux[id].el_gamal_pk
                );
            }
        }

        // The resulting sum of masks should be zero, since the combined secret key
        // should not change after applying the masks at each node.
        let mask_sum: Scalar = changes
            .values()
            .map(|change| change.secret_share_change.expose_secret())
            .sum();
        assert_eq!(mask_sum, Scalar::ZERO);
    }
}
