use crypto_bigint::Pow;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::paillier::{
    uint::{mul_mod, CheckedAdd, CheckedMul, NonZero, Retrieve, UintLike, UintModLike},
    Ciphertext, PaillierParams, PublicKeyPaillier, SecretKeyPaillier, Signed,
};
use crate::sigma::params::SchemeParams;
use crate::tools::hashing::{Chain, Hash, Hashable};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicKeyPaillier<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "PublicKeyPaillier<P::Paillier>: for<'x> Deserialize<'x>"))]
pub(crate) struct EncProof<P: SchemeParams> {
    cap_s: <P::Paillier as PaillierParams>::DoubleUint,
    cap_a: Ciphertext<P::Paillier>,
    cap_c: <P::Paillier as PaillierParams>::DoubleUint,
    z1: Signed<<P::Paillier as PaillierParams>::DoubleUint>,
    z2: <P::Paillier as PaillierParams>::DoubleUint,
    z3: <P::Paillier as PaillierParams>::DoubleUint,
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
        let aux_sk = SecretKeyPaillier::<P::Paillier>::random(&mut aux_rng);
        let aux_pk = aux_sk.public_key(); // `\hat{N}`

        let rr = aux_pk.random_invertible_group_elem(&mut aux_rng);
        let lambda = aux_sk.random_field_elem(&mut aux_rng);
        // TODO: use `square()` when it's available
        let rp_generator = rr * rr; // `t`
        let rp_power = rp_generator.pow(&lambda); // `s`

        // Non-interactive challenge ($e$)
        let challenge = Signed::<<P::Paillier as PaillierParams>::DoubleUint>::random_bounded(
            &mut aux_rng,
            &NonZero::new(P::CURVE_ORDER).unwrap(),
        );

        // TODO: check that `bound` and `bound_eps` do not overflow the DoubleUint
        // TODO: check that `secret` is within `+- 2^bound`

        let hat_phi = aux_sk.totient();
        let hat_modulus_mod_phi =
            <P::Paillier as PaillierParams>::DoubleUintMod::new(&aux_pk.modulus(), &hat_phi);

        // \alpha <-- +- 2^{\ell + \eps}
        // CHECK: should we instead sample in range $+- 2^{\ell + \eps} - q 2^\ell$?
        // This will ensure that the range check on the prover side will pass.
        let alpha = Signed::<<P::Paillier as PaillierParams>::DoubleUint>::random_bounded_bits(
            rng,
            P::L_BOUND + P::EPS_BOUND,
        );

        // \mu <-- (+- 2^\ell) * \hat{N}
        // It will be used only as an exponent mod \hat{N} so we can pre-reduce it mod \hat{\phi}
        let mu_random_part =
            Signed::<<P::Paillier as PaillierParams>::DoubleUint>::random_bounded_bits(
                rng,
                P::L_BOUND,
            )
            .extract_mod(&hat_phi);
        let mu_mod = hat_modulus_mod_phi
            * <P::Paillier as PaillierParams>::DoubleUintMod::new(&mu_random_part, &hat_phi);
        let mu = mu_mod.retrieve();

        // r <-- Z^*_N (N is the modulus of `pk`)
        let r = pk.random_invertible_group_elem(rng);

        // \gamma <-- (+- 2^{\ell + \eps}) * \hat{N}
        // It will be used only as an exponent mod \hat{N} so we can pre-reduce it mod \hat{\phi}
        let gamma_random_part =
            Signed::<<P::Paillier as PaillierParams>::DoubleUint>::random_bounded_bits(
                rng,
                P::L_BOUND + P::EPS_BOUND,
            )
            .extract_mod(&hat_phi);
        let gamma_mod = hat_modulus_mod_phi
            * <P::Paillier as PaillierParams>::DoubleUintMod::new(&gamma_random_part, &hat_phi);
        let gamma = gamma_mod.retrieve();

        // S = s^k * t^\mu \mod \hat{N}
        let cap_s = (rp_power.pow(secret) * rp_generator.pow(&mu)).retrieve();

        // A = (1 + N_0)^\alpha * r^N_0 == encrypt(\alpha, r)
        let cap_a =
            Ciphertext::new_with_randomizer(&pk, &alpha.extract_mod(&pk.modulus()), &r.retrieve());

        // C = s^\alpha * t^\gamma \mod \hat{N}
        let cap_c =
            (rp_power.pow(&alpha.extract_mod(&hat_phi)) * rp_generator.pow(&gamma)).retrieve();

        // z_1 = \alpha + e k
        // In the proof it will be checked that $z1 \in +- 2^{\ell + \eps}$,
        // so it should fit into DoubleUint.
        let secret_signed = Signed::new_positive(*secret).unwrap();
        let z1 = alpha
            .checked_add(challenge.checked_mul(secret_signed).unwrap())
            .unwrap();

        // z_2 = r * \rho^e mod N_0
        let randomizer_mod =
            <P::Paillier as PaillierParams>::DoubleUintMod::new(randomizer, &pk.modulus());
        let z2 = (r * randomizer_mod.pow(&challenge.extract_mod(&sk.totient()))).retrieve();

        // z_3 = \gamma + e * \mu
        let z3 = gamma.add_mod(
            &mul_mod(&mu, &challenge.extract_mod(&hat_phi), &hat_phi),
            &hat_phi,
        );

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

        let rr = aux_pk.random_invertible_group_elem(&mut aux_rng);
        let lambda = aux_sk.random_field_elem(&mut aux_rng);
        // TODO: use `square()` when it's available
        let rp_generator = rr * rr; // `t`
        let rp_power = rp_generator.pow(&lambda); // `s`

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
        let c = Ciphertext::new_with_randomizer(pk, &self.z1.extract_mod(&pk.modulus()), &self.z2);

        if c != self
            .cap_a
            .homomorphic_add(pk, &ciphertext.homomorphic_mul_signed(pk, &challenge))
        {
            return false;
        }

        // Check that $s^{z_1} t^{z_3} == C S^e \mod \hat{N}$
        let cap_c_mod =
            <P::Paillier as PaillierParams>::DoubleUintMod::new(&self.cap_c, &aux_pk.modulus());
        let cap_s_mod =
            <P::Paillier as PaillierParams>::DoubleUintMod::new(&self.cap_s, &aux_pk.modulus());

        if rp_power.pow(&self.z1.extract_mod(&aux_sk.totient())) * rp_generator.pow(&self.z3)
            != cap_c_mod * cap_s_mod.pow(&challenge.extract_mod(&aux_sk.totient()))
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::EncProof;
    use crate::paillier::{
        uint::{NonZero, RandomMod},
        Ciphertext, PaillierParams, SecretKeyPaillier,
    };
    use crate::sigma::params::{SchemeParams, TestSchemeParams};

    #[test]
    fn prove_and_verify() {
        type Params = TestSchemeParams;
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
