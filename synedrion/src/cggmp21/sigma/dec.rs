//! Paillier decryption modulo $q$ ($\Pi^{dec}$, Section C.6, Fig. 30)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::{
    curve::Scalar,
    paillier::{
        Ciphertext, CiphertextWire, PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams, Randomizer,
        RandomizerWire,
    },
    tools::hashing::{Chain, Hashable, XofHasher},
    uint::Signed,
};

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
    cap_s: RPCommitmentWire<P::Paillier>,
    cap_t: RPCommitmentWire<P::Paillier>,
    cap_a: CiphertextWire<P::Paillier>,
    gamma: Scalar,
    z1: Signed<<P::Paillier as PaillierParams>::WideUint>,
    z2: Signed<<P::Paillier as PaillierParams>::WideUint>,
    omega: RandomizerWire<P::Paillier>,
}

impl<P: SchemeParams> DecProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        y: &Signed<<P::Paillier as PaillierParams>::Uint>,
        rho: &Randomizer<P::Paillier>,
        pk0: &PublicKeyPaillier<P::Paillier>,
        x: &Scalar,
        cap_c: &Ciphertext<P::Paillier>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        assert_eq!(cap_c.public_key(), pk0);

        let hat_cap_n = &setup.modulus_bounded(); // $\hat{N}$

        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);
        let nu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let r = Randomizer::random(rng, pk0);

        let cap_s = setup.commit(y, &mu).to_wire();
        let cap_t = setup.commit(&alpha, &nu).to_wire();
        let cap_a = Ciphertext::new_with_randomizer_signed(pk0, &alpha, &r.to_wire()).to_wire();
        let gamma = P::scalar_from_signed(&alpha);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            // NOTE: the paper only says "sends (A, gamma) to the verifier",
            // but clearly S and T are sent too since the verifier needs access to them.
            // So they're also being hashed as commitments.
            .chain(&cap_s)
            .chain(&cap_t)
            .chain(&cap_a)
            .chain(&gamma)
            // public parameters
            .chain(pk0.as_wire())
            .chain(x)
            .chain(&cap_c.to_wire())
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = alpha.into_wide() + e.mul_wide(y);
        let z2 = nu + e.into_wide() * mu;

        let omega = (r * rho.pow_signed_vartime(&e)).to_wire();

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
        pk0: &PublicKeyPaillier<P::Paillier>,
        x: &Scalar,
        cap_c: &Ciphertext<P::Paillier>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> bool {
        assert_eq!(cap_c.public_key(), pk0);

        let mut reader = XofHasher::new_with_dst(HASH_TAG)
            // commitments
            .chain(&self.cap_s)
            .chain(&self.cap_t)
            .chain(&self.cap_a)
            .chain(&self.gamma)
            // public parameters
            .chain(pk0.as_wire())
            .chain(x)
            .chain(&cap_c.to_wire())
            .chain(&setup.to_wire())
            .chain(aux)
            .finalize_to_reader();

        // Non-interactive challenge
        let e = Signed::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // enc(z_1, \omega) == A (+) C (*) e
        if Ciphertext::new_with_randomizer_wide(pk0, &self.z1, &self.omega)
            != self.cap_a.to_precomputed(pk0) + cap_c * e
        {
            return false;
        }

        // z_1 == \gamma + e x \mod q
        if P::scalar_from_wide_signed(&self.z1) != self.gamma + P::scalar_from_signed(&e) * *x {
            return false;
        }

        // s^{z_1} t^{z_2} == T S^e
        let cap_s_mod = self.cap_s.to_precomputed(setup);
        let cap_t_mod = self.cap_t.to_precomputed(setup);
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
    use crate::{
        cggmp21::{SchemeParams, TestParams},
        paillier::{Ciphertext, PaillierParams, RPParams, Randomizer, SecretKeyPaillierWire},
        uint::Signed,
    };

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut OsRng).into_precomputed();
        let pk = sk.public_key();

        let setup = RPParams::random(&mut OsRng);

        let aux: &[u8] = b"abcde";

        // We need something within the range -N/2..N/2 so that it doesn't wrap around.
        let y = Signed::random_bounded_bits(&mut OsRng, Paillier::PRIME_BITS * 2 - 2);
        let x = Params::scalar_from_signed(&y);

        let rho = Randomizer::random(&mut OsRng, pk);
        let cap_c = Ciphertext::new_with_randomizer_signed(pk, &y, &rho.to_wire());

        let proof = DecProof::<Params>::new(&mut OsRng, &y, &rho, pk, &x, &cap_c, &setup, &aux);
        assert!(proof.verify(pk, &x, &cap_c, &setup, &aux));
    }
}
