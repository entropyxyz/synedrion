//! KeyRefresh protocol, in the paper Auxiliary Info. & Key Refresh in Three Rounds (Fig. 6).
//! This protocol generates an update to the secret key shares and new auxiliary parameters
//! for ZK proofs (e.g. Paillier keys).

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use crypto_bigint::BitOps;
use manul::protocol::{
    Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome, LocalError,
    NormalBroadcast, PartyId, Payload, Protocol, ProtocolError, ProtocolMessagePart, ProtocolValidationError,
    ReceiveError, Round, RoundId, Serializer,
};
use rand_core::CryptoRngCore;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};

use super::{
    entities::{AuxInfo, KeyShareChange, PublicAuxInfo, SecretAuxInfo},
    params::SchemeParams,
    sigma::{FacProof, ModProof, PrmProof, SchCommitment, SchProof, SchSecret},
};
use crate::{
    curve::{Point, Scalar},
    paillier::{
        Ciphertext, CiphertextWire, PublicKeyPaillier, PublicKeyPaillierWire, RPParams, RPParamsWire, RPSecret,
        RandomizerWire, SecretKeyPaillier, SecretKeyPaillierWire,
    },
    tools::{
        bitvec::BitVec,
        hashing::{Chain, FofHasher, HashOutput},
        DowncastMap, Without,
    },
};

/// A protocol for generating auxiliary information for signing,
/// and a simultaneous generation of updates for the secret key shares.
#[derive(Debug)]
pub struct KeyRefreshProtocol<P: SchemeParams, I: PartyId>(PhantomData<(P, I)>);

impl<P: SchemeParams, I: PartyId> Protocol for KeyRefreshProtocol<P, I> {
    type Result = (KeyShareChange<P, I>, AuxInfo<P, I>);
    type ProtocolError = KeyRefreshError<P>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    KeyRefreshErrorEnum<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    KeyRefreshErrorEnum<P>: for<'x> Deserialize<'x>,
"))]
pub struct KeyRefreshError<P: SchemeParams>(KeyRefreshErrorEnum<P>);

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        cap_c: CiphertextWire<P::Paillier>,
        x: Scalar,
        mu: RandomizerWire<P::Paillier>,
    },
}

impl<P: SchemeParams> ProtocolError for KeyRefreshError<P> {
    fn description(&self) -> String {
        unimplemented!()
    }

    fn required_direct_messages(&self) -> BTreeSet<RoundId> {
        unimplemented!()
    }

    fn required_echo_broadcasts(&self) -> BTreeSet<RoundId> {
        unimplemented!()
    }

    fn required_combined_echos(&self) -> BTreeSet<RoundId> {
        unimplemented!()
    }

    fn verify_messages_constitute_error(
        &self,
        _deserializer: &Deserializer,
        _echo_broadcast: &EchoBroadcast,
        _normal_broadcat: &NormalBroadcast,
        _direct_message: &DirectMessage,
        _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        _normal_broadcasts: &BTreeMap<RoundId, NormalBroadcast>,
        _direct_messages: &BTreeMap<RoundId, DirectMessage>,
        _combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        unimplemented!()
    }
}

/// An entry point for the [`KeyRefreshProtocol`].
#[derive(Debug, Clone)]
pub struct KeyRefresh<P, I> {
    all_ids: BTreeSet<I>,
    phantom: PhantomData<P>,
}

impl<P, I: PartyId> KeyRefresh<P, I> {
    /// Creates a new entry point given the set of the participants' IDs
    /// (including this node's).
    pub fn new(all_ids: BTreeSet<I>) -> Result<Self, LocalError> {
        Ok(Self {
            all_ids,
            phantom: PhantomData,
        })
    }
}

impl<P: SchemeParams, I: PartyId> EntryPoint<I> for KeyRefresh<P, I> {
    type Protocol = KeyRefreshProtocol<P, I>;

    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: &I,
    ) -> Result<BoxedRound<I, Self::Protocol>, LocalError> {
        if !self.all_ids.contains(id) {
            return Err(LocalError::new("The given node IDs must contain this node's ID"));
        }

        let other_ids = self.all_ids.clone().without(id);

        let ids_ordering = self
            .all_ids
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, id)| (id, idx))
            .collect();

        let sid_hash = FofHasher::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&self.all_ids)
            .finalize();

        // $p_i$, $q_i$
        let paillier_sk = SecretKeyPaillierWire::<P::Paillier>::random(rng);
        // $N_i$
        let paillier_pk = paillier_sk.public_key();

        // El-Gamal key
        let y = Scalar::random(rng);
        let cap_y = y.mul_by_generator();

        // The secret and the commitment for the Schnorr PoK of the El-Gamal key
        let tau_y = SchSecret::random(rng); // $\tau$
        let cap_b = SchCommitment::new(&tau_y);

        // Secret share updates for each node ($x_i^j$ where $i$ is this party's index).
        let x_to_send = self
            .all_ids
            .iter()
            .cloned()
            .zip(Scalar::ZERO.split(rng, self.all_ids.len()))
            .collect::<BTreeMap<_, _>>();

        // Public counterparts of secret share updates ($X_i^j$ where $i$ is this party's index).
        let cap_x_to_send = x_to_send.values().map(|x| x.mul_by_generator()).collect();

        let rp_secret = RPSecret::random(rng);
        // Ring-Pedersen parameters ($s$, $t$) bundled in a single object.
        let rp_params = RPParams::random_with_secret(rng, &rp_secret);

        let aux = (&sid_hash, id);
        let hat_psi = PrmProof::<P>::new(rng, &rp_secret, &rp_params, &aux);

        // The secrets share changes ($\tau_j$, not to be confused with $\tau$)
        let tau_x = self
            .all_ids
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
            paillier_pk: paillier_pk.clone(),
            rp_params: rp_params.to_wire(),
            hat_psi,
            rho,
            u,
        };

        let data_precomp = PublicData1Precomp {
            data,
            paillier_pk: paillier_pk.into_precomputed(),
            rp_params,
        };

        let context = Context {
            paillier_sk: paillier_sk.into_precomputed(),
            y,
            x_to_send,
            tau_x,
            tau_y,
            data_precomp,
            my_id: id.clone(),
            other_ids,
            sid_hash,
            ids_ordering,
        };

        Ok(BoxedRound::new_dynamic(Round1 { context }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
        PrmProof<P>: Serialize,
    "))]
#[serde(bound(deserialize = "
        PrmProof<P>: for<'x> Deserialize<'x>,
    "))]
struct PublicData1<P: SchemeParams> {
    cap_x_to_send: Vec<Point>,         // $X_i^j$ where $i$ is this party's index
    cap_a_to_send: Vec<SchCommitment>, // $A_i^j$ where $i$ is this party's index
    cap_y: Point,
    cap_b: SchCommitment,
    paillier_pk: PublicKeyPaillierWire<P::Paillier>, // $N_i$
    rp_params: RPParamsWire<P::Paillier>,            // $s_i$ and $t_i$
    hat_psi: PrmProof<P>,
    rho: BitVec,
    u: BitVec,
}

#[derive(Debug, Clone)]
struct PublicData1Precomp<P: SchemeParams> {
    data: PublicData1<P>,
    paillier_pk: PublicKeyPaillier<P::Paillier>,
    rp_params: RPParams<P::Paillier>,
}

#[derive(Debug)]
struct Context<P: SchemeParams, I> {
    paillier_sk: SecretKeyPaillier<P::Paillier>,
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

#[derive(Debug)]
struct Round1<P: SchemeParams, I> {
    context: Context<P, I>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round1Message {
    cap_v: HashOutput,
}

struct Round1Payload {
    cap_v: HashOutput,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round1<P, I> {
    type Protocol = KeyRefreshProtocol<P, I>;

    fn id(&self) -> RoundId {
        RoundId::new(1)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::from([RoundId::new(2)])
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        EchoBroadcast::new(
            serializer,
            Round1Message {
                cap_v: self
                    .context
                    .data_precomp
                    .data
                    .hash(&self.context.sid_hash, &self.context.my_id),
            },
        )
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        _from: &I,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        normal_broadcast.assert_is_none()?;
        direct_message.assert_is_none()?;
        let echo_broadcast = echo_broadcast.deserialize::<Round1Message>(deserializer)?;
        Ok(Payload::new(Round1Payload {
            cap_v: echo_broadcast.cap_v,
        }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round1Payload>()?;
        let others_cap_v = payloads.into_iter().map(|(id, payload)| (id, payload.cap_v)).collect();
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round2 {
            context: self.context,
            others_cap_v,
        })))
    }
}

#[derive(Debug)]
struct Round2<P: SchemeParams, I> {
    context: Context<P, I>,
    others_cap_v: BTreeMap<I, HashOutput>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicData1<P>: Serialize"))]
#[serde(bound(deserialize = "PublicData1<P>: for<'x> Deserialize<'x>"))]
struct Round2Message<P: SchemeParams> {
    data: PublicData1<P>,
}

struct Round2Payload<P: SchemeParams> {
    data: PublicData1Precomp<P>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round2<P, I> {
    type Protocol = KeyRefreshProtocol<P, I>;

    fn id(&self) -> RoundId {
        RoundId::new(2)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::from([RoundId::new(3)])
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn make_normal_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<NormalBroadcast, LocalError> {
        NormalBroadcast::new(
            serializer,
            Round2Message {
                data: self.context.data_precomp.data.clone(),
            },
        )
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &I,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        echo_broadcast.assert_is_none()?;
        direct_message.assert_is_none()?;
        let normal_broadcast = normal_broadcast.deserialize::<Round2Message<P>>(deserializer)?;
        let cap_v = self
            .others_cap_v
            .get(from)
            .ok_or_else(|| LocalError::new(format!("Missing `V` for {from:?}")))?;

        if &normal_broadcast.data.hash(&self.context.sid_hash, from) != cap_v {
            return Err(ReceiveError::protocol(KeyRefreshError(KeyRefreshErrorEnum::Round2(
                "Hash mismatch".into(),
            ))));
        }

        let paillier_pk = normal_broadcast.data.paillier_pk.clone().into_precomputed();

        if (paillier_pk.modulus().bits_vartime() as usize) < 8 * P::SECURITY_PARAMETER {
            return Err(ReceiveError::protocol(KeyRefreshError(KeyRefreshErrorEnum::Round2(
                "Paillier modulus is too small".into(),
            ))));
        }

        if normal_broadcast.data.cap_x_to_send.iter().sum::<Point>() != Point::IDENTITY {
            return Err(ReceiveError::protocol(KeyRefreshError(KeyRefreshErrorEnum::Round2(
                "Sum of X points is not identity".into(),
            ))));
        }

        let aux = (&self.context.sid_hash, &from);

        let rp_params = normal_broadcast.data.rp_params.to_precomputed();
        if !normal_broadcast.data.hat_psi.verify(&rp_params, &aux) {
            return Err(ReceiveError::protocol(KeyRefreshError(KeyRefreshErrorEnum::Round2(
                "PRM verification failed".into(),
            ))));
        }

        Ok(Payload::new(Round2Payload {
            data: PublicData1Precomp {
                data: normal_broadcast.data,
                paillier_pk,
                rp_params,
            },
        }))
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round2Payload<P>>()?;
        let others_data = payloads
            .into_iter()
            .map(|(id, payload)| (id, payload.data))
            .collect::<BTreeMap<_, _>>();
        let mut rho = self.context.data_precomp.data.rho.clone();
        for data in others_data.values() {
            rho ^= &data.data.rho;
        }

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round3::new(
            rng,
            self.context,
            others_data,
            rho,
        ))))
    }
}

#[derive(Debug)]
struct Round3<P: SchemeParams, I> {
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
    CiphertextWire<P::Paillier>: Serialize,
"))]
#[serde(bound(deserialize = "
    ModProof<P>: for<'x> Deserialize<'x>,
    FacProof<P>: for<'x> Deserialize<'x>,
    CiphertextWire<P::Paillier>: for<'x> Deserialize<'x>,
"))]
struct PublicData2<P: SchemeParams> {
    psi_mod: ModProof<P>, // $\psi_i$, a P^{mod} for the Paillier modulus
    phi: FacProof<P>,
    pi: SchProof,
    paillier_enc_x: CiphertextWire<P::Paillier>, // `C_j,i`
    psi_sch: SchProof,                           // $psi_i^j$, a P^{sch} for the secret share change
}

impl<P: SchemeParams, I: PartyId> Round3<P, I> {
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
struct Round3Message<P: SchemeParams> {
    data2: PublicData2<P>,
}

struct Round3Payload {
    x: Scalar, // $x_j^i$, a secret share change received from the party $j$
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round3<P, I> {
    type Protocol = KeyRefreshProtocol<P, I>;

    fn id(&self) -> RoundId {
        RoundId::new(3)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn may_produce_result(&self) -> bool {
        true
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &I,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let aux = (&self.context.sid_hash, &self.context.my_id, &self.rho);

        let data = self
            .others_data
            .get(destination)
            .ok_or_else(|| LocalError::new(format!("Missing data for {destination:?}")))?;

        let phi = FacProof::new(rng, &self.context.paillier_sk, &data.rp_params, &aux);

        let destination_idx = self.context.ids_ordering[destination];

        let x_secret = self.context.x_to_send[destination];
        let x_public = self.context.data_precomp.data.cap_x_to_send[destination_idx];
        let ciphertext = Ciphertext::new(rng, &data.paillier_pk, &P::uint_from_scalar(&x_secret));

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
            paillier_enc_x: ciphertext.to_wire(),
            psi_sch,
        };

        let dm = DirectMessage::new(serializer, Round3Message { data2 })?;
        Ok((dm, None))
    }

    fn receive_message(
        &self,
        rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &I,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        echo_broadcast.assert_is_none()?;
        normal_broadcast.assert_is_none()?;
        let direct_message = direct_message.deserialize::<Round3Message<P>>(deserializer)?;

        let sender_data = &self
            .others_data
            .get(from)
            .ok_or_else(|| LocalError::new(format!("Missing data for {from:?}")))?;

        let enc_x = direct_message
            .data2
            .paillier_enc_x
            .to_precomputed(&self.context.data_precomp.paillier_pk);

        let x = P::scalar_from_uint(&enc_x.decrypt(&self.context.paillier_sk));

        let my_idx = self.context.ids_ordering[&self.context.my_id];

        if x.mul_by_generator() != sender_data.data.cap_x_to_send[my_idx] {
            let mu = enc_x.derive_randomizer(&self.context.paillier_sk);
            return Err(ReceiveError::protocol(KeyRefreshError(
                KeyRefreshErrorEnum::Round3MismatchedSecret {
                    cap_c: direct_message.data2.paillier_enc_x,
                    x,
                    mu: mu.to_wire(),
                },
            )));
        }

        let aux = (&self.context.sid_hash, &from, &self.rho);

        if !direct_message.data2.psi_mod.verify(rng, &sender_data.paillier_pk, &aux) {
            return Err(ReceiveError::protocol(KeyRefreshError(KeyRefreshErrorEnum::Round3(
                "Mod proof verification failed".into(),
            ))));
        }

        if !direct_message
            .data2
            .phi
            .verify(&sender_data.paillier_pk, &self.context.data_precomp.rp_params, &aux)
        {
            return Err(ReceiveError::protocol(KeyRefreshError(KeyRefreshErrorEnum::Round3(
                "Fac proof verification failed".into(),
            ))));
        }

        if !direct_message
            .data2
            .pi
            .verify(&sender_data.data.cap_b, &sender_data.data.cap_y, &aux)
        {
            return Err(ReceiveError::protocol(KeyRefreshError(KeyRefreshErrorEnum::Round3(
                "Sch proof verification (Y) failed".into(),
            ))));
        }

        if !direct_message.data2.psi_sch.verify(
            &sender_data.data.cap_a_to_send[my_idx],
            &sender_data.data.cap_x_to_send[my_idx],
            &aux,
        ) {
            return Err(ReceiveError::protocol(KeyRefreshError(KeyRefreshErrorEnum::Round3(
                "Sch proof verification (X) failed".into(),
            ))));
        }

        Ok(Payload::new(Round3Payload { x }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round3Payload>()?;
        let others_x = payloads
            .into_iter()
            .map(|(id, payload)| (id, payload.x))
            .collect::<BTreeMap<_, _>>();

        // The combined secret share change
        let x_star = others_x.values().sum::<Scalar>() + self.context.x_to_send[&self.context.my_id];

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
                    all_data.values().map(|data| data.data.cap_x_to_send[idx]).sum(),
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
                        paillier_pk: data.paillier_pk.into_wire(),
                        rp_params: data.rp_params.to_wire(),
                    },
                )
            })
            .collect();

        let secret_aux = SecretAuxInfo {
            paillier_sk: self.context.paillier_sk.into_wire(),
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

        Ok(FinalizeOutcome::Result((key_share_change, aux_info)))
    }
}

#[cfg(test)]
mod tests {

    use alloc::collections::{BTreeMap, BTreeSet};

    use manul::{
        dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
        session::signature::Keypair,
    };
    use rand_core::OsRng;
    use secrecy::ExposeSecret;

    use super::KeyRefresh;
    use crate::{cggmp21::TestParams, curve::Scalar};

    #[test]
    fn execute_key_refresh() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();

        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| {
                let entry_point = KeyRefresh::<TestParams, TestVerifier>::new(all_ids.clone()).unwrap();
                (signer, entry_point)
            })
            .collect::<Vec<_>>();

        let results = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        let (changes, aux_infos): (BTreeMap<_, _>, BTreeMap<_, _>) = results
            .into_iter()
            .map(|(id, (change, aux))| ((id, change), (id, aux)))
            .unzip();

        // Check that public points correspond to secret scalars
        for (id, change) in changes.iter() {
            for other_change in changes.values() {
                assert_eq!(
                    change.secret_share_change.expose_secret().mul_by_generator(),
                    other_change.public_share_changes[id]
                );
            }
        }

        for (id, aux_info) in aux_infos.iter() {
            for other_aux_info in aux_infos.values() {
                assert_eq!(
                    aux_info.secret_aux.el_gamal_sk.expose_secret().mul_by_generator(),
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