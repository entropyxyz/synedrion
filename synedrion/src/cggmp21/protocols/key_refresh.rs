//! KeyRefresh protocol, in the paper Auxiliary Info. & Key Refresh in Three Rounds (Fig. 6).
//! This protocol generates an update to the secret key shares and new auxiliary parameters
//! for ZK proofs (e.g. Paillier keys).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::cggmp21::{
    sigma::{FacProof, ModProof, PrmProof, SchCommitment, SchProof, SchSecret},
    SchemeParams,
};
use crate::common::{KeyShareChange, PublicAuxInfo, SecretAuxInfo};
use crate::curve::{Point, Scalar};
use crate::paillier::{
    Ciphertext, CiphertextMod, PublicKeyPaillier, PublicKeyPaillierPrecomputed, RPParams,
    RPParamsMod, RPSecret, Randomizer, SecretKeyPaillier, SecretKeyPaillierPrecomputed,
};
use crate::rounds::{
    all_parties_except, try_to_holevec, FinalizableToNextRound, FinalizableToResult, FinalizeError,
    FirstRound, InitError, PartyIdx, ProtocolResult, ReceiveError, Round, ToNextRound, ToResult,
};
use crate::tools::bitvec::BitVec;
use crate::tools::collections::HoleVec;
use crate::tools::hashing::{Chain, Hash, HashOutput, Hashable};
use crate::uint::UintLike;

/// Possible results of the KeyRefresh protocol.
#[derive(Debug, Clone, Copy)]
pub struct KeyRefreshResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for KeyRefreshResult<P> {
    type Success = KeyShareChange<P>;
    type ProvableError = KeyRefreshError<P>;
    type CorrectnessProof = ();
}

#[derive(Debug, Clone)]
pub struct KeyRefreshError<P: SchemeParams>(KeyRefreshErrorEnum<P>);

#[derive(Debug, Clone)]
enum KeyRefreshErrorEnum<P: SchemeParams> {
    Round2(String),
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
#[serde(bound(serialize = "PrmProof<P>: Serialize"))]
#[serde(bound(deserialize = "PrmProof<P>: for<'x> Deserialize<'x>"))]
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

struct Context<P: SchemeParams> {
    paillier_sk: SecretKeyPaillierPrecomputed<P::Paillier>,
    y: Scalar,
    x_to_send: Vec<Scalar>, // $x_i^j$ where $i$ is this party's index
    tau_y: SchSecret,
    tau_x: Vec<SchSecret>,
    data_precomp: PublicData1Precomp<P>,
    party_idx: PartyIdx,
    num_parties: usize,
    sid_hash: HashOutput,
}

impl<P: SchemeParams> Hashable for PublicData1<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest
            .chain(&self.cap_x_to_send)
            .chain(&self.cap_a_to_send)
            .chain(&self.cap_y)
            .chain(&self.cap_b)
            .chain(&self.paillier_pk)
            .chain(&self.rp_params)
            .chain(&self.hat_psi)
            .chain(&self.rho)
            .chain(&self.u)
    }
}

impl<P: SchemeParams> PublicData1<P> {
    fn hash(&self, sid_hash: &HashOutput, party_idx: PartyIdx) -> HashOutput {
        Hash::new_with_dst(b"Auxiliary")
            .chain(sid_hash)
            .chain(&party_idx)
            .chain(self)
            .finalize()
    }
}

pub struct Round1<P: SchemeParams> {
    context: Context<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Inputs = ();
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        _inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let sid_hash = Hash::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&(u32::try_from(num_parties).unwrap()))
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
        let x_to_send = Scalar::ZERO.split(rng, num_parties);
        // Public counterparts of secret share updates ($X_i^j$ where $i$ is this party's index).
        let cap_x_to_send = x_to_send
            .iter()
            .cloned()
            .map(|x| x.mul_by_generator())
            .collect::<Vec<_>>();

        let lambda = RPSecret::random(rng, &paillier_sk);
        // Ring-Pedersen parameters ($s$, $t$) bundled in a single object.
        let rp_params = RPParamsMod::random_with_secret(rng, &lambda, paillier_pk);

        let aux = (&sid_hash, &party_idx);
        let hat_psi = PrmProof::<P>::new(rng, &paillier_sk, &lambda, &rp_params, &aux);

        // The secrets share changes ($\tau_j$, not to be confused with $\tau$)
        let tau_x: Vec<SchSecret> = (0..num_parties).map(|_| SchSecret::random(rng)).collect();

        // The commitments for share changes ($A_i^j$ where $i$ is this party's index)
        let cap_a_to_send = tau_x.iter().map(SchCommitment::new).collect();

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
            party_idx,
            num_parties,
            sid_hash,
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

impl<P: SchemeParams> Round for Round1<P> {
    type Type = ToNextRound;
    type Result = KeyRefreshResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn num_parties(&self) -> usize {
        self.context.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.party_idx
    }

    const REQUIRES_ECHO: bool = true;
    type Message = Round1Message;
    type Payload = Round1Payload;
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(self.context.num_parties, self.context.party_idx)
    }

    fn make_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        _destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artifact), String> {
        Ok((
            Round1Message {
                cap_v: self
                    .context
                    .data_precomp
                    .data
                    .hash(&self.context.sid_hash, self.party_idx()),
            },
            (),
        ))
    }

    fn verify_message(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        Ok(Round1Payload { cap_v: msg.cap_v })
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round1<P> {
    type NextRound = Round2<P>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let others_cap_v = try_to_holevec(payloads, self.num_parties(), self.party_idx())
            .unwrap()
            .map(|payload| payload.cap_v);
        Ok(Round2 {
            context: self.context,
            others_cap_v,
        })
    }
}

pub struct Round2<P: SchemeParams> {
    context: Context<P>,
    others_cap_v: HoleVec<HashOutput>,
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

impl<P: SchemeParams> Round for Round2<P> {
    type Type = ToNextRound;
    type Result = KeyRefreshResult<P>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn num_parties(&self) -> usize {
        self.context.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.party_idx
    }

    type Message = Round2Message<P>;
    type Payload = Round2Payload<P>;
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(self.context.num_parties, self.context.party_idx)
    }

    fn make_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        _destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artifact), String> {
        Ok((
            Round2Message {
                data: self.context.data_precomp.data.clone(),
            },
            (),
        ))
    }

    fn verify_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        if &msg.data.hash(&self.context.sid_hash, from)
            != self.others_cap_v.get(from.as_usize()).unwrap()
        {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round2("Hash mismatch".into()),
            )));
        }

        let paillier_pk = msg.data.paillier_pk.to_precomputed();

        if paillier_pk.modulus().bits_vartime() < 8 * P::SECURITY_PARAMETER {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round2("Paillier modulus is too small".into()),
            )));
        }

        if msg.data.cap_x_to_send.iter().sum::<Point>() != Point::IDENTITY {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round2("Sum of X points is not identity".into()),
            )));
        }

        let aux = (&self.context.sid_hash, &from);

        let rp_params = msg.data.rp_params.to_mod(&paillier_pk);
        if !msg.data.hat_psi.verify(&rp_params, &aux) {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round2("PRM verification failed".into()),
            )));
        }

        Ok(Round2Payload {
            data: PublicData1Precomp {
                data: msg.data,
                paillier_pk,
                rp_params,
            },
        })
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round2<P> {
    type NextRound = Round3<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let others_data = try_to_holevec(payloads, self.num_parties(), self.party_idx())
            .unwrap()
            .map(|payload| payload.data);
        let mut rho = self.context.data_precomp.data.rho.clone();
        for data in others_data.iter() {
            rho ^= &data.data.rho;
        }

        Ok(Round3::new(rng, self.context, others_data, rho))
    }
}

pub struct Round3<P: SchemeParams> {
    context: Context<P>,
    rho: BitVec,
    others_data: HoleVec<PublicData1Precomp<P>>,
    psi_mod: ModProof<P>,
    pi: SchProof,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ModProof<P>: Serialize,
    FacProof<P>: Serialize,
    Ciphertext<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "ModProof<P>: for<'x> Deserialize<'x>,
    FacProof<P>: for<'x> Deserialize<'x>,
    Ciphertext<P::Paillier>: for<'x> Deserialize<'x>"))]
pub struct PublicData2<P: SchemeParams> {
    psi_mod: ModProof<P>, // $\psi_i$, a P^{mod} for the Paillier modulus
    phi: FacProof<P>,
    pi: SchProof,
    paillier_enc_x: Ciphertext<P::Paillier>, // `C_j,i`
    psi_sch: SchProof,                       // $psi_i^j$, a P^{sch} for the secret share change
}

impl<P: SchemeParams> Round3<P> {
    fn new(
        rng: &mut impl CryptoRngCore,
        context: Context<P>,
        others_data: HoleVec<PublicData1Precomp<P>>,
        rho: BitVec,
    ) -> Self {
        let aux = (&context.sid_hash, &context.party_idx, &rho);
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

impl<P: SchemeParams> Round for Round3<P> {
    type Type = ToResult;
    type Result = KeyRefreshResult<P>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn num_parties(&self) -> usize {
        self.context.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.party_idx
    }

    type Message = Round3Message<P>;
    type Payload = Round3Payload;
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(self.context.num_parties, self.context.party_idx)
    }

    fn make_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artifact), String> {
        let aux = (&self.context.sid_hash, &self.context.party_idx, &self.rho);

        let idx = destination.as_usize();
        let data = self.others_data.get(idx).unwrap();

        let phi = FacProof::new(
            rng,
            &self.context.paillier_sk,
            &self.others_data.get(idx).unwrap().rp_params,
            &aux,
        );

        let x_secret = self.context.x_to_send[idx];
        let x_public = self.context.data_precomp.data.cap_x_to_send[idx];
        let ciphertext =
            CiphertextMod::new(rng, &data.paillier_pk, &P::uint_from_scalar(&x_secret));

        let psi_sch = SchProof::new(
            &self.context.tau_x[idx],
            &x_secret,
            &self.context.data_precomp.data.cap_a_to_send[idx],
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

        Ok((Round3Message { data2 }, ()))
    }

    fn verify_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        let sender_data = &self.others_data.get(from.as_usize()).unwrap();

        let enc_x = msg
            .data2
            .paillier_enc_x
            .to_mod(self.context.paillier_sk.public_key());

        let x = P::scalar_from_uint(&enc_x.decrypt(&self.context.paillier_sk));

        if x.mul_by_generator() != sender_data.data.cap_x_to_send[self.context.party_idx.as_usize()]
        {
            let mu = enc_x.derive_randomizer(&self.context.paillier_sk);
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3MismatchedSecret {
                    cap_c: msg.data2.paillier_enc_x,
                    x,
                    mu: mu.retrieve(),
                },
            )));
        }

        let aux = (&self.context.sid_hash, &from, &self.rho);

        if !msg.data2.psi_mod.verify(&sender_data.paillier_pk, &aux) {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3("Mod proof verification failed".into()),
            )));
        }

        if !msg.data2.phi.verify(
            &sender_data.paillier_pk,
            &self.context.data_precomp.rp_params,
            &aux,
        ) {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3("Fac proof verification failed".into()),
            )));
        }

        if !msg
            .data2
            .pi
            .verify(&sender_data.data.cap_b, &sender_data.data.cap_y, &aux)
        {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3("Sch proof verification (Y) failed".into()),
            )));
        }

        if !msg.data2.psi_sch.verify(
            &sender_data.data.cap_a_to_send[self.context.party_idx.as_usize()],
            &sender_data.data.cap_x_to_send[self.context.party_idx.as_usize()],
            &aux,
        ) {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3("Sch proof verification (X) failed".into()),
            )));
        }

        Ok(Round3Payload { x })
    }
}

impl<P: SchemeParams> FinalizableToResult for Round3<P> {
    fn finalize_to_result(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let others_x = try_to_holevec(payloads, self.num_parties(), self.party_idx())
            .unwrap()
            .map(|payload| payload.x);

        // The combined secret share change
        let x_star = others_x.iter().sum::<Scalar>()
            + self.context.x_to_send[self.context.party_idx.as_usize()];

        let all_data = self.others_data.into_vec(self.context.data_precomp);

        // The combined public share changes for each node
        let cap_x_star = (0..all_data.len())
            .map(|idx| {
                all_data
                    .iter()
                    .map(|data| data.data.cap_x_to_send[idx])
                    .sum()
            })
            .collect::<Box<_>>();

        let public_aux = all_data
            .into_iter()
            .map(|data| PublicAuxInfo {
                el_gamal_pk: data.data.cap_y,
                paillier_pk: data.paillier_pk.to_minimal(),
                rp_params: data.rp_params.retrieve(),
            })
            .collect();

        let secret_aux = SecretAuxInfo {
            paillier_sk: self.context.paillier_sk.to_minimal(),
            el_gamal_sk: self.context.y,
        };

        let key_share_change = KeyShareChange {
            index: self.context.party_idx,
            secret_share_change: x_star,
            public_share_changes: cap_x_star,
            secret_aux,
            public_aux,
        };

        Ok(key_share_change)
    }
}

#[cfg(test)]
mod tests {

    use rand_core::{OsRng, RngCore};

    use super::Round1;
    use crate::cggmp21::TestParams;
    use crate::curve::Scalar;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round},
        FirstRound, PartyIdx,
    };

    #[test]
    fn execute_auxiliary() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 3;
        let r1 = (0..num_parties)
            .map(|idx| {
                Round1::<TestParams>::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    (),
                )
                .unwrap()
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let changes = step_result(&mut OsRng, r3a).unwrap();

        // Check that public points correspond to secret scalars
        for (idx, change) in changes.iter().enumerate() {
            for other_change in changes.iter() {
                assert_eq!(
                    change.secret_share_change.mul_by_generator(),
                    other_change.public_share_changes[idx]
                );
                assert_eq!(
                    change.secret_aux.el_gamal_sk.mul_by_generator(),
                    other_change.public_aux[idx].el_gamal_pk
                );
            }
        }

        // The resulting sum of masks should be zero, since the combined secret key
        // should not change after applying the masks at each node.
        let mask_sum: Scalar = changes
            .iter()
            .map(|change| change.secret_share_change)
            .sum();
        assert_eq!(mask_sum, Scalar::ZERO);
    }
}
