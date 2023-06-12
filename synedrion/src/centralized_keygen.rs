use alloc::boxed::Box;
use alloc::vec::Vec;

use rand_core::CryptoRngCore;

use crate::curve::{Point, Scalar};
use crate::paillier::uint::Zero;
use crate::paillier::{PaillierParams, SecretKeyPaillier};
use crate::protocols::common::{KeyShare, KeySharePublic, KeyShareSecret, SchemeParams};
use crate::protocols::threshold::ThresholdKeyShare;
use crate::tools::sss::{shamir_evaluation_points, shamir_split};
use crate::PartyIdx;

#[allow(clippy::type_complexity)]
fn make_key_shares_from_secrets<P: SchemeParams>(
    rng: &mut impl CryptoRngCore,
    secrets: &[Scalar],
) -> (Box<[KeyShareSecret<P>]>, Box<[KeySharePublic<P>]>) {
    let paillier_sks = secrets
        .iter()
        .map(|_| SecretKeyPaillier::<P::Paillier>::random(rng))
        .collect::<Vec<_>>();

    let public = secrets
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

    let secret = secrets
        .iter()
        .zip(paillier_sks.iter())
        .map(|(secret, sk)| KeyShareSecret {
            secret: *secret,
            sk: (*sk).clone(),
            y: Scalar::random(rng), // TODO: currently unused in the protocol
        })
        .collect();

    (secret, public)
}

/// Returns `num_parties` of random self-consistent key shares
/// (which in a decentralized case would be the output of KeyGen + Auxiliary protocols).
pub fn make_key_shares<P: SchemeParams>(
    rng: &mut impl CryptoRngCore,
    num_parties: usize,
    signing_key: Option<&k256::ecdsa::SigningKey>,
) -> Box<[KeyShare<P>]> {
    let secret = match signing_key {
        None => Scalar::random(rng),
        Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
    };

    let secrets = secret.split(rng, num_parties);

    let (secret_shares, public_shares) = make_key_shares_from_secrets(rng, &secrets);

    secret_shares
        .into_vec()
        .into_iter()
        .enumerate()
        .map(|(idx, secret)| KeyShare {
            index: PartyIdx::from_usize(idx),
            secret,
            public: public_shares.clone(),
        })
        .collect()
}

pub fn make_threshold_key_shares<P: SchemeParams>(
    rng: &mut impl CryptoRngCore,
    threshold: usize,
    num_parties: usize,
    signing_key: Option<&k256::ecdsa::SigningKey>,
) -> Box<[ThresholdKeyShare<P>]> {
    debug_assert!(threshold <= num_parties);

    let secret = match signing_key {
        None => Scalar::random(rng),
        Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
    };

    let secrets = shamir_split(
        rng,
        &secret,
        threshold,
        &shamir_evaluation_points(num_parties),
    );

    let (secret_shares, public_shares) = make_key_shares_from_secrets(rng, &secrets);

    secret_shares
        .into_vec()
        .into_iter()
        .enumerate()
        .map(|(idx, secret)| ThresholdKeyShare {
            index: PartyIdx::from_usize(idx),
            threshold: threshold as u32, // TODO: fallible conversion?
            secret,
            public: public_shares.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    use super::{make_key_shares, make_threshold_key_shares};
    use crate::curve::Scalar;
    use crate::{PartyIdx, TestSchemeParams};

    #[test]
    fn make_shares_for_signing_key() {
        let sk = SigningKey::random(&mut OsRng);
        let shares = make_key_shares::<TestSchemeParams>(&mut OsRng, 3, Some(&sk));
        assert_eq!(&shares[0].verifying_key(), sk.verifying_key());
    }

    #[test]
    fn make_threshold_shares_for_signing_key() {
        let sk = SigningKey::random(&mut OsRng);
        let shares = make_threshold_key_shares::<TestSchemeParams>(&mut OsRng, 2, 3, Some(&sk));
        assert_eq!(&shares[0].verifying_key(), sk.verifying_key());

        let nt_share0 = shares[0].to_key_share(&[PartyIdx::from_usize(2), PartyIdx::from_usize(0)]);
        let nt_share1 = shares[2].to_key_share(&[PartyIdx::from_usize(2), PartyIdx::from_usize(0)]);

        assert_eq!(&nt_share0.verifying_key(), sk.verifying_key());
        assert_eq!(&nt_share1.verifying_key(), sk.verifying_key());
        assert_eq!(
            nt_share0.secret.secret + nt_share1.secret.secret,
            Scalar::from(sk.as_nonzero_scalar())
        );
    }
}
