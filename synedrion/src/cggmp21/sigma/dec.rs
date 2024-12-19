//! Paillier decryption modulo $q$ ($\Pi^{dec}$, Section C.6, Fig. 30)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    conversion::{scalar_from_signed, scalar_from_wide_signed, secret_scalar_from_signed},
    SchemeParams,
};
use crate::{
    curve::Scalar,
    paillier::{
        Ciphertext, CiphertextWire, MaskedRandomizer, PaillierParams, PublicKeyPaillier, RPCommitmentWire, RPParams,
        Randomizer,
    },
    tools::hashing::{Chain, Hashable, XofHasher},
    uint::{PublicSigned, SecretSigned},
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
    e: PublicSigned<<P::Paillier as PaillierParams>::Uint>,
    cap_s: RPCommitmentWire<P::Paillier>,
    cap_t: RPCommitmentWire<P::Paillier>,
    cap_a: CiphertextWire<P::Paillier>,
    gamma: Scalar,
    z1: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    z2: PublicSigned<<P::Paillier as PaillierParams>::WideUint>,
    omega: MaskedRandomizer<P::Paillier>,
}

impl<P: SchemeParams> DecProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rng: &mut impl CryptoRngCore,
        y: &SecretSigned<<P::Paillier as PaillierParams>::Uint>,
        rho: &Randomizer<P::Paillier>,
        pk0: &PublicKeyPaillier<P::Paillier>,
        x: &Scalar,
        cap_c: &Ciphertext<P::Paillier>,
        setup: &RPParams<P::Paillier>,
        aux: &impl Hashable,
    ) -> Self {
        assert_eq!(cap_c.public_key(), pk0);

        let hat_cap_n = setup.modulus(); // $\hat{N}$

        let alpha = SecretSigned::random_in_exp_range(rng, P::L_BOUND + P::EPS_BOUND);
        let mu = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND, hat_cap_n);
        let nu = SecretSigned::random_in_exp_range_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);
        let r = Randomizer::random(rng, pk0);

        let cap_s = setup.commit(y, &mu).to_wire();
        let cap_t = setup.commit(&alpha, &nu).to_wire();
        let cap_a = Ciphertext::new_with_randomizer_signed(pk0, &alpha, &r).to_wire();

        // `alpha` is secret, but `gamma` only uncovers $\ell$ bits of `alpha`'s full $\ell + \eps$ bits,
        // and it's transmitted to another node, so it can be considered public.
        let gamma = *secret_scalar_from_signed::<P>(&alpha).expose_secret();

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
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        let z1 = (alpha.to_wide() + y.mul_wide(&e)).to_public();
        let z2 = (nu + mu * e.to_wide()).to_public();

        let omega = rho.to_masked(&r, &e);

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
        let e = PublicSigned::from_xof_reader_bounded(&mut reader, &P::CURVE_ORDER);

        if e != self.e {
            return false;
        }

        // enc(z_1, \omega) == A (+) C (*) e
        if Ciphertext::new_public_with_randomizer_wide(pk0, &self.z1, &self.omega)
            != self.cap_a.to_precomputed(pk0) + cap_c * &e
        {
            return false;
        }

        // z_1 == \gamma + e x \mod q
        if scalar_from_wide_signed::<P>(&self.z1) != self.gamma + scalar_from_signed::<P>(&e) * *x {
            return false;
        }

        // s^{z_1} t^{z_2} == T S^e
        let cap_s = self.cap_s.to_precomputed(setup);
        let cap_t = self.cap_t.to_precomputed(setup);
        if setup.commit(&self.z1, &self.z2) != &cap_t * &cap_s.pow(&e) {
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
        cggmp21::{conversion::secret_scalar_from_signed, SchemeParams, TestParams},
        paillier::{Ciphertext, PaillierParams, RPParams, Randomizer, SecretKeyPaillierWire},
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

        // We need something within the range -N/2..N/2 so that it doesn't wrap around.
        let y = SecretSigned::random_in_exp_range(&mut OsRng, Paillier::PRIME_BITS * 2 - 2);
        let x = *secret_scalar_from_signed::<Params>(&y).expose_secret();

        let rho = Randomizer::random(&mut OsRng, pk);
        let cap_c = Ciphertext::new_with_randomizer_signed(pk, &y, &rho);

        let proof = DecProof::<Params>::new(&mut OsRng, &y, &rho, pk, &x, &cap_c, &setup, &aux);
        assert!(proof.verify(pk, &x, &cap_c, &setup, &aux));
    }
}
