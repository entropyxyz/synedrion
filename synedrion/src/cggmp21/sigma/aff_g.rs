//! Paillier Affine Operation with Group Commitment in Range ($\Pi^{aff-g}$, Section 6.2, Fig. 15)

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::SchemeParams;
use crate::curve::Point;
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillierPrecomputed, RPCommitment, RPParamsMod,
};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::uint::{FromScalar, NonZero, Retrieve, Signed, UintModLike};

// TODO: should it be here? Or in `curve`?
// Or a separate function so that `uint` and `curve` are agnostic of each other?
pub(crate) fn mul_by_point<P: SchemeParams>(
    p: &Point,
    x: &Signed<<P::Paillier as PaillierParams>::Uint>,
) -> Point {
    // TODO: should we have a method in `FromScalar` that does the reduction too?
    let scalar = (x.abs() % NonZero::new(P::CURVE_ORDER).unwrap()).to_scalar();

    // TODO: make constant-time
    let scalar = if x.is_negative().into() {
        -scalar
    } else {
        scalar
    };

    p * &scalar
}

pub(crate) fn mul_by_generator<P: SchemeParams>(
    x: &Signed<<P::Paillier as PaillierParams>::Uint>,
) -> Point {
    mul_by_point::<P>(&Point::GENERATOR, x)
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AffGProof<P: SchemeParams> {
    cap_a: Ciphertext<P::Paillier>,                        // $A$
    cap_b_x: Point,                                        // $B_x$
    cap_b_y: Ciphertext<P::Paillier>,                      // $B_y$
    cap_e: RPCommitment<P::Paillier>,                      // $E$
    cap_s: RPCommitment<P::Paillier>,                      // $S$
    cap_f: RPCommitment<P::Paillier>,                      // $F$
    cap_t: RPCommitment<P::Paillier>,                      // $T$
    z1: Signed<<P::Paillier as PaillierParams>::Uint>,     // $z_1$
    z2: Signed<<P::Paillier as PaillierParams>::Uint>,     // $z_2$
    z3: Signed<<P::Paillier as PaillierParams>::WideUint>, // $z_3$
    z4: Signed<<P::Paillier as PaillierParams>::WideUint>, // $z_4$
    omega: <P::Paillier as PaillierParams>::Uint,          // $\omega$
    omega_y: <P::Paillier as PaillierParams>::Uint,        // $\omega_y$
}

impl<P: SchemeParams> AffGProof<P> {
    #[allow(clippy::too_many_arguments)]
    pub fn random(
        rng: &mut impl CryptoRngCore,
        x: &Signed<<P::Paillier as PaillierParams>::Uint>, // $x \in +- 2^\ell$
        y: &Signed<<P::Paillier as PaillierParams>::Uint>, // $y \in +- 2^{\ell^\prime}$
        rho: &<P::Paillier as PaillierParams>::Uint,       // $\rho \in \mathbb{Z}_{N_0}$
        rho_y: &<P::Paillier as PaillierParams>::Uint,     // $\rho_y \in \mathbb{Z}_{N_1}$
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,   // $N_0$
        pk1: &PublicKeyPaillierPrecomputed<P::Paillier>,   // $N_1$
        // CHECK: while the paper does not impose any restrictions on it,
        // if `cap_c = encrypt(s)`, then we should have
        // - `|s \alpha + \beta| < N_0 / 2
        // - `|s (\alpha + e x) + \beta + e y| < N_0 / 2
        cap_c: &Ciphertext<P::Paillier>, // a ciphertext encrypted with `pk0`
        aux_rp: &RPParamsMod<P::Paillier>, // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> Self {
        // TODO: check ranges of input values

        let mut aux_rng = Hash::new_with_dst(b"P_aff_g").chain(aux).finalize_to_rng();

        let hat_cap_n = &aux_rp.public_key().modulus_nonzero(); // $\hat{N}$

        // Non-interactive challenge ($e$)
        let challenge =
            Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());
        let challenge_wide: Signed<<P::Paillier as PaillierParams>::WideUint> =
            challenge.into_wide();

        // \alpha <-- +- 2^{\ell + \eps}
        let alpha = Signed::random_bounded_bits(rng, P::L_BOUND + P::EPS_BOUND);

        // \beta <-- +- 2^{\ell^\prime + \eps}
        let beta = Signed::random_bounded_bits(rng, P::LP_BOUND + P::EPS_BOUND);

        // TODO: use `Ciphertext::randomizer()`
        // r <-- Z^*_{N_0}
        let r = pk0.random_invertible_group_elem(rng);
        // r_y <-- Z^*_{N_1}
        let r_y = pk1.random_invertible_group_elem(rng);

        // \gamma <-- (+- 2^{\ell + \eps}) \hat{N}
        let gamma = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        // m <-- (+- 2^\ell) \hat{N}
        let m = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        // \delta <-- (+- 2^{\ell + \eps}) \hat{N}
        let delta = Signed::random_bounded_bits_scaled(rng, P::L_BOUND + P::EPS_BOUND, hat_cap_n);

        // \mu <-- (+- 2^\ell) \hat{N}
        let mu = Signed::random_bounded_bits_scaled(rng, P::L_BOUND, hat_cap_n);

        // A = C^\alpha (1 + N_0)^\beta r^N_0 \mod N_0^2
        //   = C (*) \alpha (+) encrypt_0(\beta, r)
        let cap_a = cap_c.homomorphic_mul(pk0, &alpha).homomorphic_add(
            pk0,
            &Ciphertext::new_with_randomizer_signed(pk0, &beta, &r.retrieve()),
        );

        // B_x = g^\alpha
        let cap_b_x = mul_by_generator::<P>(&alpha);

        // B_y = (1 + N_1)^\beta r_y^{N_1} \mod N_1^2
        let cap_b_y = Ciphertext::new_with_randomizer_signed(pk1, &beta, &r_y.retrieve());

        // E = s^\alpha t^\gamma \mod \hat{N}
        let cap_e = aux_rp.commit(&gamma, &alpha).retrieve();

        // S = s^x t^m  \mod \hat{N}
        let cap_s = aux_rp.commit(&m, x).retrieve();

        // F = s^\beta t^\delta \mod \hat{N}
        let cap_f = aux_rp.commit(&delta, &beta).retrieve();

        // CHECK: deviation from the paper to support a different `D`
        // Original: `s^y`. Modified: `s^{-y}`
        // T = s^{-y} t^\mu \mod \hat{N}
        let cap_t = aux_rp.commit(&mu, &-y).retrieve();

        // z_1 = \alpha + e x
        let z1 = alpha + challenge * *x;

        // CHECK: deviation from the paper to support a different `D`
        // Original: z_2 = \beta + e y
        // Modified: z_2 = \beta - e y
        let z2 = beta + challenge * (-y);

        // z_3 = \gamma + e m
        let z3 = gamma + challenge_wide * m;

        // z_4 = \delta + e \mu
        let z4 = delta + challenge_wide * mu;

        // \omega = r \rho^e \mod N_0
        let rho_mod = <P::Paillier as PaillierParams>::UintMod::new(rho, pk0.precomputed_modulus());
        let omega = (r * rho_mod.pow_signed_vartime(&challenge)).retrieve();

        // CHECK: deviation from the paper to support a different `D`
        // Original: `\rho_y^e`. Modified: `\rho_y^{-e}`.
        // \omega_y = r_y \rho_y^{-e} \mod N_1
        let rho_y_mod =
            <P::Paillier as PaillierParams>::UintMod::new(rho_y, pk1.precomputed_modulus());
        let omega_y = (r_y * rho_y_mod.pow_signed_vartime(&-challenge)).retrieve();

        Self {
            cap_a,
            cap_b_x,
            cap_b_y,
            cap_e,
            cap_s,
            cap_f,
            cap_t,
            z1,
            z2,
            z3,
            z4,
            omega,
            omega_y,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        pk0: &PublicKeyPaillierPrecomputed<P::Paillier>,
        pk1: &PublicKeyPaillierPrecomputed<P::Paillier>,
        cap_c: &Ciphertext<P::Paillier>,
        // CHECK: deviation from the paper here.
        // The proof in the paper assumes $D = C (*) x (+) enc_0(y, \rho)$.
        // But the way it is used in the Presigning, $D$ will actually be $... (+) enc_0(-y, \rho)$.
        // So we have to negate several variables when constructing the proof
        // for the whole thing to work.
        cap_d: &Ciphertext<P::Paillier>, // $D = C (*) x (+) enc_0(-y, \rho)$
        cap_y: &Ciphertext<P::Paillier>, // $Y = enc_1(y, \rho_y)$
        cap_x: &Point,                   // $X = g * x$, where `g` is the curve generator
        aux_rp: &RPParamsMod<P::Paillier>, // $\hat{N}$, $s$, $t$
        aux: &impl Hashable,
    ) -> bool {
        let mut aux_rng = Hash::new_with_dst(b"P_aff_g").chain(aux).finalize_to_rng();

        let aux_pk = aux_rp.public_key();

        // Non-interactive challenge ($e$)
        let challenge =
            Signed::random_bounded(&mut aux_rng, &NonZero::new(P::CURVE_ORDER).unwrap());

        // C^{z_1} (1 + N_0)^{z_2} \omega^{N_0} = A D^e \mod N_0^2
        // => C (*) z_1 (+) encrypt_0(z_2, \omega) = A (+) D (*) e
        if cap_c.homomorphic_mul(pk0, &self.z1).homomorphic_add(
            pk0,
            &Ciphertext::new_with_randomizer_signed(pk0, &self.z2, &self.omega),
        ) != cap_d
            .homomorphic_mul(pk0, &challenge)
            .homomorphic_add(pk0, &self.cap_a)
        {
            return false;
        }

        // g^{z_1} = B_x X^e
        if mul_by_generator::<P>(&self.z1) != self.cap_b_x + mul_by_point::<P>(cap_x, &challenge) {
            return false;
        }

        // CHECK: deviation from the paper to support a different `D`
        // Original: `Y^e`. Modified `Y^{-e}`.
        // (1 + N_1)^{z_2} \omega_y^{N_1} = B_y Y^(-e) \mod N_1^2
        // => encrypt_1(z_2, \omega_y) = B_y (+) Y (*) (-e)
        if Ciphertext::new_with_randomizer_signed(pk1, &self.z2, &self.omega_y)
            != cap_y
                .homomorphic_mul(pk1, &-challenge)
                .homomorphic_add(pk1, &self.cap_b_y)
        {
            return false;
        }

        // s^{z_1} t^{z_3} = E S^e \mod \hat{N}
        if aux_rp.commit(&self.z3, &self.z1)
            != &self.cap_e.to_mod(aux_pk)
                * &self.cap_s.to_mod(aux_pk).pow_signed_vartime(&challenge)
        {
            return false;
        }

        // s^{z_2} t^{z_4} = F T^e \mod \hat{N}
        if aux_rp.commit(&self.z4, &self.z2)
            != &self.cap_f.to_mod(aux_pk)
                * &self.cap_t.to_mod(aux_pk).pow_signed_vartime(&challenge)
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{mul_by_generator, AffGProof};
    use crate::cggmp21::{SchemeParams, TestParams};
    use crate::paillier::{Ciphertext, RPParamsMod, SecretKeyPaillier};
    use crate::uint::Signed;

    #[test]
    fn prove_and_verify() {
        type Params = TestParams;
        type Paillier = <Params as SchemeParams>::Paillier;

        let sk0 = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk0 = sk0.public_key();

        let sk1 = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let pk1 = sk1.public_key();

        let aux_sk = SecretKeyPaillier::<Paillier>::random(&mut OsRng).to_precomputed();
        let aux_rp = RPParamsMod::random(&mut OsRng, &aux_sk);

        let aux: &[u8] = b"abcde";

        let x = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let y = Signed::random_bounded_bits(&mut OsRng, Params::LP_BOUND);

        let rho = Ciphertext::<Paillier>::randomizer(&mut OsRng, pk0);
        let rho_y = Ciphertext::<Paillier>::randomizer(&mut OsRng, pk1);
        // TODO: use full range (0 to N)
        let secret = Signed::random_bounded_bits(&mut OsRng, Params::L_BOUND);
        let cap_c = Ciphertext::new_signed(&mut OsRng, pk0, &secret);

        let cap_d = cap_c
            .homomorphic_mul(pk0, &x)
            .homomorphic_add(pk0, &Ciphertext::new_with_randomizer_signed(pk0, &-y, &rho));
        let cap_y = Ciphertext::new_with_randomizer_signed(pk1, &y, &rho_y);
        let cap_x = mul_by_generator::<Params>(&x);

        let proof = AffGProof::<Params>::random(
            &mut OsRng, &x, &y, &rho, &rho_y, pk0, pk1, &cap_c, &aux_rp, &aux,
        );
        assert!(proof.verify(pk0, pk1, &cap_c, &cap_d, &cap_y, &cap_x, &aux_rp, &aux));
    }
}
