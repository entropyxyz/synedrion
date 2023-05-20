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
    signing_key: Option<&k256::ecdsa::SigningKey>,
) -> Box<[KeyShare<P>]> {
    let mut secrets = (0..num_parties)
        .map(|_| Scalar::random(rng))
        .collect::<Vec<_>>();

    if let Some(sk) = signing_key {
        // TODO: merge with `zero_sum_scalars()` into a function
        // producing a vec of scalars with the given sum?
        // TODO: does it panic for `num_parties = 1`?
        let partial_sum: Scalar = secrets[1..].iter().sum();
        secrets[0] = Scalar::from(sk.as_nonzero_scalar()) + (-partial_sum);
    }

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

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    use super::make_key_shares;
    use crate::TestSchemeParams;

    #[test]
    fn make_shares_for_siging_key() {
        let sk = SigningKey::random(&mut OsRng);
        let shares = make_key_shares::<TestSchemeParams>(&mut OsRng, 3, Some(&sk));
        assert_eq!(&shares[0].verifying_key(), sk.verifying_key());
    }
}
