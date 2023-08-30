use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillier, RPCommitment, RPParamsMod, SecretKeyPaillier,
};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::uint::{NonZero, Retrieve, Signed, UintModLike};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct EncProof<P: SchemeParams> {
    cap_s: RPCommitment<P::Paillier>,
    cap_a: Ciphertext<P::Paillier>,
    cap_c: RPCommitment<P::Paillier>,
    z1: Signed<<P::Paillier as PaillierParams>::DoubleUint>,
    z2: <P::Paillier as PaillierParams>::DoubleUint,
    z3: Signed<<P::Paillier as PaillierParams>::QuadUint>,
}

impl<P: SchemeParams> EncProof<P> {
    pub fn random(
        rng: &mut impl CryptoRngCore,
        secret: &<P::Paillier as PaillierParams>::DoubleUint, // `k`
        randomizer: &<P::Paillier as PaillierParams>::DoubleUint, // `\rho`
        sk: &SecretKeyPaillier<P::Paillier>,                  // `N_0`
        aux: &impl Hashable, // CHECK: used to derive `\hat{N}, s, t`
    ) -> Self {
        let pk = sk.public_key();

        let mut aux_rng = Hash::new_with_dst(b"P_enc").chain(aux).finalize_to_rng();
        let aux_sk = SecretKeyPaillier::random(&mut aux_rng);
        let aux_pk = aux_sk.public_key(); // `\hat{N}`

        let rp = RPParamsMod::random(&mut aux_rng, &aux_sk);

        // Non-interactive challenge ($e$)
        let challenge =
            Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // TODO: check that `bound` and `bound_eps` do not overflow the DoubleUint
        // TODO: check that `secret` is within `+- 2^bound`

        let secret_signed = Signed::new_positive(*secret).unwrap();

        // \alpha <-- +- 2^{\ell + \eps}
        // CHECK: should we instead sample in range $+- 2^{\ell + \eps} - q 2^\ell$?
        // This will ensure that the range check on the prover side will pass.
        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);

        // \mu <-- (+- 2^\ell) * \hat{N}
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, &aux_pk.modulus());

        // TODO: use `Ciphertext::randomizer()` - but we will need a variation returning a modulo
        // representation.
        // r <-- Z^*_N (N is the modulus of `pk`)
        let r = pk.random_invertible_group_elem(rng);

        // \gamma <-- (+- 2^{\ell + \eps}) * \hat{N}
        let gamma =
            Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, &aux_pk.modulus());

        // S = s^k * t^\mu \mod \hat{N}
        let cap_s = rp.commit(&mu, &secret_signed).retrieve();

        // A = (1 + N_0)^\alpha * r^N_0 == encrypt(\alpha, r)
        let cap_a = Ciphertext::new_with_randomizer_signed(&pk, &alpha, &r.retrieve());

        // C = s^\alpha * t^\gamma \mod \hat{N}
        let cap_c = rp.commit(&gamma, &alpha).retrieve();

        // z_1 = \alpha + e k
        // In the proof it will be checked that $z1 \in +- 2^{\ell + \eps}$,
        // so it should fit into DoubleUint.
        let z1 = alpha + challenge * secret_signed;

        // z_2 = r * \rho^e mod N_0
        let randomizer_mod =
            <P::Paillier as PaillierParams>::DoubleUintMod::new(randomizer, &pk.modulus());
        let z2 = (r * randomizer_mod.pow_signed(&challenge)).retrieve();

        // z_3 = \gamma + e * \mu
        let challenge_wide: Signed<<P::Paillier as PaillierParams>::QuadUint> =
            challenge.into_wide();
        let z3 = gamma + mu * challenge_wide;

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
        pk: &PublicKeyPaillier<P::Paillier>,  // `N_0`
        ciphertext: &Ciphertext<P::Paillier>, // `K`
        aux: &impl Hashable,                  // CHECK: used to derive `\hat{N}, s, t`
    ) -> bool {
        let mut aux_rng = Hash::new_with_dst(b"P_enc").chain(aux).finalize_to_rng();
        let aux_sk = SecretKeyPaillier::<P::Paillier>::random(&mut aux_rng);
        let aux_pk = aux_sk.public_key(); // `\hat{N}`

        let rp = RPParamsMod::random(&mut aux_rng, &aux_sk);

        // Non-interactive challenge ($e$)
        let challenge = Signed::<<P::Paillier as PaillierParams>::DoubleUint>::random_bounded(
            &mut aux_rng,
            &NonZero::new(P::CURVE_ORDER).unwrap(),
        );

        // Range check
        if !self.z1.in_range_bits(P::L_BOUND + P::EPS_BOUND) {
            return false;
        }

        // Check that $encrypt_{N_0}(z1, z2) == A (+) K (*) e$
        let c = Ciphertext::new_with_randomizer_signed(pk, &self.z1, &self.z2);

        if c != self
            .cap_a
            .homomorphic_add(pk, &ciphertext.homomorphic_mul_signed(pk, &challenge))
        {
            return false;
        }

        // Check that $s^{z_1} t^{z_3} == C S^e \mod \hat{N}$
        let cap_c_mod = self.cap_c.to_mod(&aux_pk);
        let cap_s_mod = self.cap_s.to_mod(&aux_pk);
        if rp.commit(&self.z3, &self.z1) != &cap_c_mod * &cap_s_mod.pow_signed(&challenge) {
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
    use crate::paillier::{Ciphertext, PaillierParams, SecretKeyPaillier};
    use crate::uint::{NonZero, RandomMod};

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng);
        let pk = sk.public_key();

        let aux: &[u8] = b"abcde";

        let secret = <Paillier as PaillierParams>::DoubleUint::random_mod(
            &mut OsRng,
            &NonZero::new(<Paillier as PaillierParams>::DoubleUint::ONE << Params::L_BOUND)
                .unwrap(),
        );
        let randomizer = Ciphertext::<Paillier>::randomizer(&mut OsRng, &pk);
        let ciphertext = Ciphertext::new_with_randomizer(&pk, &secret, &randomizer);

        let proof = EncProof::<Params>::random(&mut OsRng, &secret, &randomizer, &sk, &aux);
        assert!(proof.verify(&pk, &ciphertext, &aux));
    }
}
