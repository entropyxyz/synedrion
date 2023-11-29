//! Paillier encryption in range ($\Pi^{enc}$, Section 6.1, Fig. 14)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment, RPParamsMod,
    Randomizer, RandomizerMod, SecretKeyPaillierPrecomputed,
};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::{NonZero, Signed};

const HASH_TAG: &[u8] = b"P_enc";

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct EncProof<P: SchemeParams> {
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
        secret: &Signed<<P::Paillier as PaillierParams>::Uint>, // $k$
        randomizer_mod: &RandomizerMod<P::Paillier>,            // $\rho$
        sk: &SecretKeyPaillierPrecomputed<P::Paillier>,         // $N_0$
        setup: &RPParamsMod<P::Paillier>,                       // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> Self {
        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e =
            Signed::from_xof_reader_bounded(&mut reader, &NonZero::new(P::CURVE_ORDER).unwrap());

        let pk = sk.public_key();
        let hat_cap_n = &setup.public_key().modulus_bounded(); // $\hat{N}$

        // TODO (#86): should we instead sample in range $+- 2^{\ell + \eps} - q 2^\ell$?
        // This will ensure that the range check on the prover side will pass.
        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let r = RandomizerMod::random(rng, pk);
        let gamma = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        let cap_s = setup.commit(&mu, secret).retrieve();
        let cap_a = Ciphertext::new_with_randomizer_signed(pk, &alpha, &r.retrieve());
        let cap_c = setup.commit(&gamma, &alpha).retrieve();

        let z1 = alpha + e * *secret;
        let z2 = (r * randomizer_mod.pow_signed_vartime(&e)).retrieve();
        let z3 = gamma + mu * e.into_wide();

        Self {
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
        pk: &PublicKeyPaillierPrecomputed<P::Paillier>, // `N_0`
        ciphertext: &Ciphertext<P::Paillier>,           // `K`
        setup: &RPParamsMod<P::Paillier>,               // $s$, $t$
        aux: &impl Hashable,
    ) -> bool {
        let mut reader = XofHash::new_with_dst(HASH_TAG)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e =
            Signed::from_xof_reader_bounded(&mut reader, &NonZero::new(P::CURVE_ORDER).unwrap());

        // z_1 \in \pm 2^{\ell + \eps}
        if !self.z1.in_range_bits(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        // enc_0(z1, z2) == A (+) K (*) e
        let c = Ciphertext::new_with_randomizer_signed(pk, &self.z1, &self.z2);
        if c != self
            .cap_a
            .homomorphic_add(pk, &ciphertext.homomorphic_mul(pk, &e))
        {
            return false;
        }

        // s^{z_1} t^{z_3} == C S^e \mod \hat{N}
        let cap_c_mod = self.cap_c.to_mod(setup.public_key());
        let cap_s_mod = self.cap_s.to_mod(setup.public_key());
        if setup.commit(&self.z3, &self.z1) != &cap_c_mod * &cap_s_mod.pow_signed_vartime(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::EncProof;
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::paillier::{Ciphertext, RPParamsMod, RandomizerMod, SecretKeyPaillier};
    use crate::uint::Signed;

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
            Ciphertext::new_with_randomizer_signed(pk, &secret, &randomizer.retrieve());

        let proof = EncProof::<Params>::new(&mut OsRng, &secret, &randomizer, &sk, &setup, &aux);
        assert!(proof.verify(pk, &ciphertext, &setup, &aux));
    }
}
