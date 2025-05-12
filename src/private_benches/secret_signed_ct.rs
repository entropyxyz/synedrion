use crypto_bigint::{NonZero, RandomMod, U128, U4096};
use dudect_bencher::{BenchRng, Class, CtRunner};
use rand::Rng;

use crate::{tools::Secret, uint::SecretSigned};
/// Is [`SecretSigned::new_positive`] constant time when the bound is kept constant and the value varies?
pub fn new_positive_with_constant_bound(runner: &mut CtRunner, rng: &mut BenchRng) {
    let bound = 127;
    let modulus = NonZero::new(U4096::ONE << bound).unwrap();
    let input_len = 20_000_000;
    let mut inputs = {
        (0..input_len)
            .map(|_| {
                // "Normal" class: a random, typically big, value.
                if rng.r#gen::<bool>() {
                    (Class::Left, Secret::init_with(|| U4096::random_mod(rng, &modulus)))
                // "Special" class: small value.
                } else {
                    (Class::Right, Secret::init_with(|| U4096::from_u128(123u128)))
                }
            })
            .collect::<Vec<(Class, Secret<U4096>)>>()
    };

    while let Some((class, value)) = inputs.pop() {
        runner.run_one(class, || SecretSigned::new_positive(value.clone(), bound));
    }
}

/// Is [`SecretSigned::new_positive`] constant time when the value is kept constant and the bound varies?
pub fn new_positive_with_constant_value(runner: &mut CtRunner, rng: &mut BenchRng) {
    let value = { Secret::init_with(|| U128::random_mod(rng, &NonZero::new(U128::ONE << 127).unwrap())) };
    let input_len = 160_000_000;
    let mut inputs = {
        (0..input_len)
            .map(|_| {
                if rng.r#gen::<bool>() {
                    // "Normal" class: random bound.
                    (Class::Left, rng.r#gen_range(0..U128::BITS - 1))
                } else {
                    // "Special" class: small value.
                    (Class::Right, 2)
                }
            })
            .collect::<Vec<(Class, u32)>>()
    };

    while let Some((class, bound)) = inputs.pop() {
        runner.run_one(class, || SecretSigned::new_positive(value.clone(), bound));
    }
}
