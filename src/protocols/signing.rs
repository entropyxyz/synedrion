use alloc::string::String;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::generic::{BroadcastRound, Round, ToSendTyped};
use crate::protocols::common::PresigningData;
use crate::tools::collections::{HoleVec, PartyIdx};
use crate::tools::group::{Point, Scalar, Signature};

pub struct Round1 {
    verifying_key: Point,
    message: Scalar,
    r: Scalar,
    s_part: Scalar,
}

impl Round1 {
    pub fn new(presigning: &PresigningData, message: &Scalar, verifying_key: &Point) -> Self {
        let r = presigning.big_r.x_coordinate();
        let s_part = &presigning.k * message + &r * &presigning.chi;
        Self {
            r,
            s_part,
            verifying_key: *verifying_key,
            message: *message,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round1Bcast {
    s_part: Scalar,
}

impl Round for Round1 {
    type Error = String;
    type Payload = Scalar;
    type Message = Round1Bcast;
    type NextRound = Signature;

    fn to_send(&self, _rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round1Bcast {
            s_part: self.s_part,
        })
    }

    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        Ok(msg.s_part)
    }

    fn finalize(self, payloads: HoleVec<Self::Payload>) -> Self::NextRound {
        let s: Scalar = payloads.iter().sum();
        let s = s + self.s_part;

        // CHECK: should `s` be normalized here?

        let sig = Signature::from_scalars(&self.r, &s).unwrap();

        if !sig.verify(&self.verifying_key, &self.message) {
            panic!("Invalid signature created");
        }

        sig
    }
}

impl BroadcastRound for Round1 {}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::Round1;
    use crate::paillier::uint::Zero;
    use crate::paillier::{PaillierParams, SecretKeyPaillier};
    use crate::protocols::common::{AuxDataPublic, SchemeParams, SessionId, TestSchemeParams};
    use crate::protocols::generic::tests::step;
    use crate::protocols::presigning;
    use crate::tools::collections::PartyIdx;
    use crate::tools::group::{Point, Scalar};

    fn make_aux_data<P: PaillierParams>(sks: &[&SecretKeyPaillier<P>]) -> Box<[AuxDataPublic<P>]> {
        sks.into_iter()
            .map(|sk| AuxDataPublic {
                y: Point::GENERATOR,
                rp_generator: P::DoubleUint::ZERO,
                rp_power: P::DoubleUint::ZERO,
                paillier_pk: sk.public_key(),
            })
            .collect()
    }

    #[test]
    fn execute_signing() {
        let session_id = SessionId::random();

        let sk1 =
            SecretKeyPaillier::<<TestSchemeParams as SchemeParams>::Paillier>::random(&mut OsRng);
        let sk2 =
            SecretKeyPaillier::<<TestSchemeParams as SchemeParams>::Paillier>::random(&mut OsRng);
        let sk3 =
            SecretKeyPaillier::<<TestSchemeParams as SchemeParams>::Paillier>::random(&mut OsRng);

        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);
        let x3 = Scalar::random(&mut OsRng);

        let aux = make_aux_data(&[&sk1, &sk2, &sk3]);

        // TODO: need to run the presigning protocol to get the consistent presigning data.
        // Repeats the code in the presigning test. Merge them somehow.

        let r1 = vec![
            presigning::Round1Part1::<TestSchemeParams>::new(
                &mut OsRng,
                &session_id,
                PartyIdx::from_usize(0),
                3,
                &x1,
                &sk1,
                &aux,
            ),
            presigning::Round1Part1::<TestSchemeParams>::new(
                &mut OsRng,
                &session_id,
                PartyIdx::from_usize(1),
                3,
                &x2,
                &sk2,
                &aux,
            ),
            presigning::Round1Part1::<TestSchemeParams>::new(
                &mut OsRng,
                &session_id,
                PartyIdx::from_usize(2),
                3,
                &x3,
                &sk3,
                &aux,
            ),
        ];

        let r1p2 = step(&mut OsRng, r1).unwrap();
        let r2 = step(&mut OsRng, r1p2).unwrap();
        let r3 = step(&mut OsRng, r2).unwrap();
        let presigning_datas = step(&mut OsRng, r3).unwrap();

        let message = Scalar::random(&mut OsRng);
        let verifying_key = (x1 + x2 + x3).mul_by_generator();

        let r1 = vec![
            Round1::new(&presigning_datas[0], &message, &verifying_key),
            Round1::new(&presigning_datas[1], &message, &verifying_key),
            Round1::new(&presigning_datas[2], &message, &verifying_key),
        ];
        let signatures = step(&mut OsRng, r1).unwrap();

        assert!(signatures
            .iter()
            .all(|sig| sig.verify(&verifying_key, &message)));
    }
}
