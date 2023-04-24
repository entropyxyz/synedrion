use alloc::boxed::Box;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};

use crate::paillier::uint::Zero;
use crate::paillier::{PaillierParams, SecretKeyPaillier};
use crate::protocols::common::{KeyShare, KeySharePublic};
use crate::tools::group::{Point, Scalar};

/// Returns `num_parties` of random self-consistent key shares
/// (which in a decentralized case would be the output of KeyGen + Auxiliary protocols).
pub fn make_key_shares<P: PaillierParams>(
    rng: &mut (impl RngCore + CryptoRng),
    num_parties: usize,
) -> Box<[KeyShare<P>]> {
    let secrets = (0..num_parties)
        .map(|_| Scalar::random(rng))
        .collect::<Vec<_>>();
    let paillier_sks = (0..num_parties)
        .map(|_| SecretKeyPaillier::<P>::random(rng))
        .collect::<Vec<_>>();

    let public: Box<[KeySharePublic<P>]> = secrets
        .iter()
        .zip(paillier_sks.iter())
        .map(|(secret, sk)| KeySharePublic {
            x: secret.mul_by_generator(),
            y: Point::GENERATOR, // TODO: currently unused in the protocol
            rp_generator: P::DoubleUint::ZERO, // TODO: currently unused in the protocol
            rp_power: P::DoubleUint::ZERO, // TODO: currently unused in the protocol
            paillier_pk: sk.public_key(),
        })
        .collect();

    secrets
        .iter()
        .zip(paillier_sks.iter())
        .map(|(secret, sk)| KeyShare {
            secret: *secret,
            sk: (*sk).clone(),
            y: Scalar::random(rng), // TODO: currently unused in the protocol
            public: public.clone(),
        })
        .collect()
}
