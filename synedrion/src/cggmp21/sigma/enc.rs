//! Paillier encryption in range ($\Pi^{enc}$, Section 6.1, Fig. 14)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::{
    paillier::{
        Ciphertext, CiphertextMod, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment,
        RPParamsMod, Randomizer, RandomizerMod,
    },
    tools::hashing::{Chain, Hashable, XofHasher},
    uint::Signed,
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
    e: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_s: RPCommitment<P::Paillier>,
    cap_a: Ciphertext<P::Paillier>,
    cap_c: RPCommitment<P::Paillier>,
    z1: Signed<<P::Paillier as PaillierParams>::Uint>,
    z2: Randomizer<P::Paillier>,
    z3: Signed<<P::Paillier as PaillierParams>::WideUint>,
}

impl<P: SchemeParams> EncProof<P> {
    pub fn new(
        rng: &mut impl CryptoRngCore,
        k: &Signed<<P::Paillier as PaillierParams>::Uint>,
        rho: &RandomizerMod<P::Paillier>,
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_k: &CiphertextMod<P::Paillier>,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        k.assert_bound(P::L_BOUND);
        assert_eq!(cap_k.public_key(), pk0);

        let hat_cap_n = &setup.public_key().modulus_bounded(); // $\hat{N}$

        // TODO (#86): should we instead sample in range $+- 2^{\ell + \eps} - q 2^\ell$?
        // This will ensure that the range check on the prover side will pass.
        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let r = RandomizerMod::random(rng, pk0);
        let gamma = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let cap_s = setup.commit(k, &mu).retrieve();
        let cap_a =
            CiphertextMod::new_with_randomizer_signed(pk0, &alpha, &r.retrieve()).retrieve();
        let cap_c = setup.commit(&alpha, &gamma).retrieve();

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&cap_s)
            .chain(&cap_a)
            .chain(&cap_c)
            // public parameters
            .chain(pk0.as_minimal())
            .chain(&cap_k.retrieve())
            .chain(&setup.retrieve())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = alpha + e * k;
        let z2 = (r * rho.pow_signed_vartime(&e)).retrieve();
        let z3 = gamma + mu * e.into_wide();

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
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_k: &CiphertextMod<P::Paillier>,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(cap_k.public_key(), pk0);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_s)
            .chain(&self.cap_a)
            .chain(&self.cap_c)
            // public parameters
            .chain(pk0.as_minimal())
            .chain(&cap_k.retrieve())
            .chain(&setup.retrieve())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // z_1 \in \pm 2^{\ell + \eps}
        if !self.z1.in_range_bits(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        // enc_0(z1, z2) == A (+) K (*) e
        let c = CiphertextMod::new_with_randomizer_signed(pk0, &self.z1, &self.z2);
        if c != self.cap_a.to_mod(pk0) + cap_k * e {
            return false;
        }

        // s^{z_1} t^{z_3} == C S^e \mod \hat{N}
        let cap_c_mod = self.cap_c.to_mod(setup.public_key());
        let cap_s_mod = self.cap_s.to_mod(setup.public_key());
        if setup.commit(&self.z1, &self.z3) != &cap_c_mod * &cap_s_mod.pow_signed_vartime(&e) {
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
        paillier::{CiphertextMod, RPParamsMod, RandomizerMod, SecretKeyPaillier},
        uint::Signed,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk = sk.public_key();

        let aux_sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let setup = RPParamsMod::random(&mut OsRng, &aux_sk);

        let aux: &[u8] = b"abcde";

        let secret = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let randomizer = RandomizerMod::random(&mut OsRng, pk);
        let ciphertext =
            CiphertextMod::new_with_randomizer_signed(pk, &secret, &randomizer.retrieve());

        let proof = EncProof::<Params>::new(
            &mut OsRng,
            &secret,
            &randomizer,
            pk,
            &ciphertext,
            &setup,
            &aux,
        );
        assert!(proof.verify(pk, &ciphertext, &setup, &aux));
    }
}
