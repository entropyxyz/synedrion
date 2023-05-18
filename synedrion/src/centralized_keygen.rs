use alloc::boxed::Box;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};

use crate::paillier::uint::Zero;
use crate::paillier::{PaillierParams, SecretKeyPaillier};
use crate::protocols::common::{KeyShare, KeySharePublic, KeyShareSecret, SchemeParams};
use crate::tools::group::{Point, Scalar};
use crate::PartyIdx;

/// Returns `num_parties` of random self-consistent key shares
/// (which in a decentralized case would be the output of KeyGen + Auxiliary protocols).
pub fn make_key_shares<P: SchemeParams>(
    rng: &mut (impl RngCore + CryptoRng),
    num_parties: usize,
) -> Box<[KeyShare<P>]> {
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

    (0..num_parties)
        .zip(secrets.iter())
        .zip(paillier_sks.iter())
        .map(|((idx, secret), sk)| KeyShare {
            index: PartyIdx::from_usize(idx),
            secret: KeyShareSecret {
                secret: *secret,
                sk: (*sk).clone(),
                y: Scalar::random(rng), // TODO: currently unused in the protocol
            },
            public: public.clone(),
        })
        .collect()
}
