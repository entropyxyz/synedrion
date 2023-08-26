use alloc::boxed::Box;

use rand_core::CryptoRngCore;

use crate::curve::Scalar;
use crate::paillier::{PaillierParams, SecretKeyPaillier};
use crate::protocols::common::{KeyShare, PublicAuxInfo, SecretAuxInfo};
use crate::protocols::threshold::ThresholdKeyShare;
use crate::sigma::params::SchemeParams;
use crate::tools::sss::{shamir_evaluation_points, shamir_split};
use crate::uint::Zero;
use crate::PartyIdx;

#[allow(clippy::type_complexity)]
fn make_aux_info<P: SchemeParams>(
    rng: &mut impl CryptoRngCore,
    num_parties: usize,
) -> (Box<[SecretAuxInfo<P>]>, Box<[PublicAuxInfo<P>]>) {
    let secret_aux = (0..num_parties)
        .map(|_| SecretAuxInfo {
            paillier_sk: SecretKeyPaillier::<P::Paillier>::random(rng),
            el_gamal_sk: Scalar::random(rng),
        })
        .collect::<Box<_>>();

    let public_aux = secret_aux
        .iter()
        .map(|secret| PublicAuxInfo {
            paillier_pk: secret.paillier_sk.public_key(),
            el_gamal_pk: secret.el_gamal_sk.mul_by_generator(),
            rp_generator: <P::Paillier as PaillierParams>::DoubleUint::ZERO, // TODO: currently unused in the protocol
            rp_power: <P::Paillier as PaillierParams>::DoubleUint::ZERO, // TODO: currently unused in the protocol
        })
        .collect();

    (secret_aux, public_aux)
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

    let secret_shares = secret.split(rng, num_parties);
    let public_shares = secret_shares
        .iter()
        .map(|s| s.mul_by_generator())
        .collect::<Box<_>>();

    let (secret_aux, public_aux) = make_aux_info(rng, num_parties);

    secret_aux
        .into_vec()
        .into_iter()
        .enumerate()
        .map(|(idx, secret_aux)| KeyShare {
            index: PartyIdx::from_usize(idx),
            secret_share: secret_shares[idx],
            public_shares: public_shares.clone(),
            secret_aux,
            public_aux: public_aux.clone(),
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

    let secret_shares = shamir_split(
        rng,
        &secret,
        threshold,
        &shamir_evaluation_points(num_parties),
    );
    let public_shares = secret_shares
        .iter()
        .map(|s| s.mul_by_generator())
        .collect::<Box<_>>();

    let (secret_aux, public_aux) = make_aux_info(rng, num_parties);

    secret_aux
        .into_vec()
        .into_iter()
        .enumerate()
        .map(|(idx, secret_aux)| ThresholdKeyShare {
            index: PartyIdx::from_usize(idx),
            threshold: threshold as u32, // TODO: fallible conversion?
            secret_share: secret_shares[idx],
            public_shares: public_shares.clone(),
            secret_aux,
            public_aux: public_aux.clone(),
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
            nt_share0.secret_share + nt_share1.secret_share,
            Scalar::from(sk.as_nonzero_scalar())
        );
    }
}
