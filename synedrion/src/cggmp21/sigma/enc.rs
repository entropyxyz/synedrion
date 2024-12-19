//! Paillier encryption in range ($\Pi^{enc}$, Section 6.1, Fig. 14)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::{
    paillier::{
        Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams,
        Randomizer,
    },
    tools::hashing::{Chain, Hashable, XofHasher},
    uint::{PublicSigned, SecretSigned},
};

const HASH_TAG: &[u8] = b"P_enc";

/**
ZK proof: Paillier encryption in range.

Secret inputs:
- $k \in \pm 2^\ell$,
- $\rho$, a Paillier randomizer for the public key $N_0$.

Public inputs:
- Paillier public key $N_0$,
- Paillier ciphertext $K = enc_0(k, \rho)$,
- Setup parameters ($\hat{N}$, $s$, $t$).
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncProof<P: SchemeParams> {
    e: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    cap_s: RPCommitmentWire<P::Paillier>,
    cap_a: CiphertextWire<P::Paillier>,
    cap_c: RPCommitmentWire<P::Paillier>,
    z1: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    z2: MaskedRandomizer<P::Paillier>,
    z3: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
}

impl<P: SchemeParams> EncProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        k: &SecretSigned<<P::Paillier as PaillierParams>::Uint>,
        rho: &Randomizer<P::Paillier>,
        pk0: &PublicKeyPaillier<P::Paillier>,
        cap_k: &Ciphertext<P::Paillier>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        k.assert_exponent_range(P::L_BOUND);
        assert_eq!(cap_k.public_key(), pk0);

        let hat_cap_n = setup.modulus(); // $\hat{N}$

        // TODO (#86): should we instead sample in range $+- 2^{\ell + \eps} - q 2^\ell$?
        // This will ensure that the range check on the prover side will pass.
        let alpha = SecretSigned::random_in_exp_range(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND, hat_cap_n);
        let r = Randomizer::random(rng, pk0);
        let gamma = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let cap_s = setup.commit(k, &mu).to_wire();
        let cap_a = Ciphertext::new_with_randomizer_signed(pk0, &alpha, &r).to_wire();
        let cap_c = setup.commit(&alpha, &gamma).to_wire();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_s)
            .chain(&cap_a)
            .chain(&cap_c)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&cap_k.to_wire())
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = (alpha + k * e).to_public();
        let z2 = rho.to_masked(&r, &e);
        let z3 = (gamma + mu * e.to_wide()).to_public();

        Self {
            e,
            cap_s,
            cap_a,
            cap_c,
            z1,
            z2,
            z3,
        }
    }

    pub fn verify(
        &self,
        pk0: &PublicKeyPaillier<P::Paillier>,
        cap_k: &Ciphertext<P::Paillier>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(cap_k.public_key(), pk0);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_s)
            .chain(&self.cap_a)
            .chain(&self.cap_c)
            // public parameters
            .chain(pk0.as_wire())
            .chain(&cap_k.to_wire())
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // z_1 \in \pm 2^{\ell + \eps}
        if !self.z1.in_range_bits(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        // enc_0(z1, z2) == A (+) K (*) e
        let c = Ciphertext::new_public_with_randomizer_signed(pk0, &self.z1, &self.z2);
        if c != self.cap_a.to_precomputed(pk0) + cap_k * &e {
            return false;
        }

        // s^{z_1} t^{z_3} == C S^e \mod \hat{N}
        let cap_c = self.cap_c.to_precomputed(setup);
        let cap_s = self.cap_s.to_precomputed(setup);
        if setup.commit(&self.z1, &self.z3) != &cap_c * &cap_s.pow(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::EncProof;
    use crate::{
        cggmp21::{SchemeParams, TestParams},
        paillier::{Ciphertext, RPParams, Randomizer, SecretKeyPaillierWire},
        uint::SecretSigned,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let setup = RPParams::random(&mut OsRng);

        let aux: &[u8] = b"abcde";

        let secret = SecretSigned::random_in_exp_range(&mut OsRng, Params::L_BOUND);
        let randomizer = Randomizer::random(&mut OsRng, pk);
        let ciphertext = Ciphertext::new_with_randomizer_signed(pk, &secret, &randomizer);

        let proof = EncProof::<Params>::new(&mut OsRng, &secret, &randomizer, pk, &ciphertext, &setup, &aux);
        assert!(proof.verify(pk, &ciphertext, &setup, &aux));
    }
}
