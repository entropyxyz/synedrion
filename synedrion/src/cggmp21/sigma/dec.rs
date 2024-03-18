//! Paillier decryption modulo $q$ ($\Pi^{dec}$, Section C.6, Fig. 30)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::curve::Scalar;
use crate::paillier::{
    Ciphertext, CiphertextMod, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment,
    RPParamsMod, Randomizer, RandomizerMod,
};
use crate::tools::hashing::{Chain, Hashable, XofHash};
use crate::uint::Signed;

const HASH_TAG: &[u8] = b"P_dec";

/**
ZK proof: Paillier decryption modulo $q$.

Secret inputs:
- $y$ (technically any integer since it will be implicitly reduced modulo $q$ or $\phi(N_0)$,
  but we limit its size to `Uint` since that's what we use in this library),
- $\rho$, a Paillier randomizer for the public key $N_0$.

Public inputs:
- Paillier public key $N_0$,
- scalar $x = y \mod q$, where $q$ is the curve order,
- Paillier ciphertext $C = enc_0(y, \rho)$,
- Setup parameters ($\hat{N}$, $s$, $t$).
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DecProof<P: SchemeParams> {
    e: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_s: RPCommitment<P::Paillier>,
    cap_t: RPCommitment<P::Paillier>,
    cap_a: Ciphertext<P::Paillier>,
    gamma: Scalar,
    z1: Signed<<P::Paillier as PaillierParams>::WideUint>,
    z2: Signed<<P::Paillier as PaillierParams>::WideUint>,
    omega: Randomizer<P::Paillier>,
}

impl<P: SchemeParams> DecProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        y: &Signed<<P::Paillier as PaillierParams>::Uint>,
        rho: &RandomizerMod<P::Paillier>,
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        x: &Scalar,
        cap_c: &CiphertextMod<P::Paillier>,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        assert_eq!(cap_c.public_key(), pk0);

        let hat_cap_n = &setup.public_key().modulus_bounded(); // $\hat{N}$

        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let nu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let r = RandomizerMod::random(rng, pk0);

        let cap_s = setup.commit(y, &mu).retrieve();
        let cap_t = setup.commit(&alpha, &nu).retrieve();
        let cap_a =
            CiphertextMod::new_with_randomizer_signed(pk0, &alpha, &r.retrieve()).retrieve();
        let gamma = P::scalar_from_signed(&alpha);

        let mut reader = XofHash::new_with_dst(HASH_TAG)
            // commitments
            // NOTE: the paper only says "sends (A, gamma) to the verifier",
            // but clearly S and T are sent too since the verifier needs access to them.
            // So they're also being hashed as commitments.
            .chain(&cap_s)
            .chain(&cap_t)
            .chain(&cap_a)
            .chain(&gamma)
            // public parameters
            .chain(pk0)
            .chain(x)
            .chain(&cap_c.retrieve())
            .chain(setup)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = alpha.into_wide() + e.mul_wide(y);
        let z2 = nu + e.into_wide() * mu;

        let omega = (r * rho.pow_signed_vartime(&e)).retrieve();

        Self {
            e,
            cap_s,
            cap_t,
            cap_a,
            gamma,
            z1,
            z2,
            omega,
        }
    }

    pub fn verify(
        &self,
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        x: &Scalar,
        cap_c: &CiphertextMod<P::Paillier>,
        setup: &RPParamsMod<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(cap_c.public_key(), pk0);

        let mut reader = XofHash::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_s)
            .chain(&self.cap_t)
            .chain(&self.cap_a)
            .chain(&self.gamma)
            // public parameters
            .chain(pk0)
            .chain(x)
            .chain(&cap_c.retrieve())
            .chain(setup)
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // enc(z_1, \omega) == A (+) C (*) e
        if CiphertextMod::new_with_randomizer_wide(pk0, &self.z1, &self.omega)
            != self.cap_a.to_mod(pk0) + cap_c * e
        {
            return false;
        }

        // z_1 == \gamma + e x \mod q
        if P::scalar_from_wide_signed(&self.z1) != self.gamma + P::scalar_from_signed(&e) * *x {
            return false;
        }

        // s^{z_1} t^{z_2} == T S^e
        let cap_s_mod = self.cap_s.to_mod(setup.public_key());
        let cap_t_mod = self.cap_t.to_mod(setup.public_key());
        if setup.commit_wide(&self.z1, &self.z2) != &cap_t_mod * &cap_s_mod.pow_signed_vartime(&e) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::DecProof;
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::paillier::{
        CiphertextMod, PaillierParams, RPParamsMod, RandomizerMod, SecretKeyPaillier,
    };
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

        // We need something within the range -N/2..N/2 so that it doesn't wrap around.
        let y = Signed::random_bounded_bits(&mut OsRng, Paillier::PRIME_BITS * 2 - 2);
        let x = Params::scalar_from_signed(&y);

        let rho = RandomizerMod::random(&mut OsRng, pk);
        let cap_c = CiphertextMod::new_with_randomizer_signed(pk, &y, &rho.retrieve());

        let proof = DecProof::<Params>::new(&mut OsRng, &y, &rho, pk, &x, &cap_c, &setup, &aux);
        assert!(proof.verify(pk, &x, &cap_c, &setup, &aux));
    }
}
