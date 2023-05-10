use alloc::boxed::Box;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};

use crate::paillier::uint::Zero;
use crate::paillier::{PaillierParams, SecretKeyPaillier};
use crate::protocols::common::{KeySharePublic, KeyShareSecret, KeyShareVectorized, SchemeParams};
use crate::sessions::{KeyShare, PartyId, ToTypedId};
use crate::tools::group::{Point, Scalar};

/// Returns `num_parties` of random self-consistent key shares
/// (which in a decentralized case would be the output of KeyGen + Auxiliary protocols).
pub fn make_key_shares_vectorized<P: SchemeParams>(
    rng: &mut (impl RngCore + CryptoRng),
    num_parties: usize,
) -> Box<[KeyShareVectorized<P>]> {
    let secrets = (0..num_parties)
        .map(|_| Scalar::random(rng))
        .collect::<Vec<_>>();
    let paillier_sks = (0..num_parties)
        .map(|_| SecretKeyPaillier::<P::Paillier>::random(rng))
        .collect::<Vec<_>>();

    let public: Box<[KeySharePublic<P>]> = secrets
        .iter()
        .zip(paillier_sks.iter())
        .map(|(secret, sk)| KeySharePublic {
            x: secret.mul_by_generator(),
            y: Point::GENERATOR, // TODO: currently unused in the protocol
            rp_generator: <P::Paillier as PaillierParams>::DoubleUint::ZERO, // TODO: currently unused in the protocol
            rp_power: <P::Paillier as PaillierParams>::DoubleUint::ZERO, // TODO: currently unused in the protocol
            paillier_pk: sk.public_key(),
        })
        .collect();

    secrets
        .iter()
        .zip(paillier_sks.iter())
        .map(|(secret, sk)| KeyShareVectorized {
            secret: KeyShareSecret {
                secret: *secret,
                sk: (*sk).clone(),
                y: Scalar::random(rng), // TODO: currently unused in the protocol
            },
            public: public.clone(),
        })
        .collect()
}

pub fn make_key_shares<Id: PartyId, P: SchemeParams>(
    rng: &mut (impl RngCore + CryptoRng),
    parties: &[Id],
) -> Box<[KeyShare<Id, P>]> {
    let shares = make_key_shares_vectorized(rng, parties.len());
    shares
        .iter()
        .cloned()
        .zip(parties.iter())
        .map(|(share, id)| share.to_typed_id(parties, id))
        .collect()
}
