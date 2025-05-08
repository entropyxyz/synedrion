use core::ops::AddAssign;

use crypto_bigint::{NonZero, RandomMod, WrappingAdd, U4096};
use dudect_bencher::{BenchRng, Class, CtRunner};
use rand::Rng;

use crate::tools::Secret;

/// Is [`Secret::init_with`] constant time? This actually tests that `clone()` and `zeroize()` are CT.
pub fn init_with(runner: &mut CtRunner, rng: &mut BenchRng) {
    let modulus = NonZero::new(U4096::ONE << 4095).unwrap();

    let input_len = 300_000_000;
    let mut inputs = (0..input_len)
        .map(|_| {
            if rng.r#gen::<bool>() {
                // "Normal" class: a random, typically big, value.
                (Class::Left, U4096::random_mod(rng, &modulus))
            } else {
                // "Special" class: small value.
                (Class::Right, U4096::ONE)
            }
        })
        .collect::<Vec<(Class, U4096)>>();

    while let Some((class, value)) = inputs.pop() {
        runner.run_one(class, || Secret::init_with(|| value));
    }
}

/// Is [`Secret::wrapping_add`] constant time?
pub fn wrapping_add(runner: &mut CtRunner, rng: &mut BenchRng) {
    let modulus = NonZero::new(U4096::MAX.shr_vartime(10)).unwrap();
    let secret = Secret::init_with(|| U4096::random_mod(rng, &modulus));
    let input_len = 100_000;
    let mut inputs = (0..input_len)
        .map(|_| {
            if rng.r#gen::<bool>() {
                // "Normal" class: a random, typically big, value.
                (Class::Left, Secret::init_with(|| U4096::random_mod(rng, &modulus)))
            } else {
                // "Special" class: small value.
                (Class::Right, Secret::init_with(|| U4096::ONE))
            }
        })
        .collect::<Vec<(Class, Secret<U4096>)>>();

    while let Some((class, rhs)) = inputs.pop() {
        runner.run_one(class, || secret.wrapping_add(&rhs));
    }
}

/// Is [`Secret::add_assign`] constant time?
pub fn add_assign(runner: &mut CtRunner, rng: &mut BenchRng) {
    let modulus = NonZero::new(U4096::MAX.shr_vartime(10)).unwrap();
    let secret = Secret::init_with(|| U4096::random_mod(rng, &modulus));
    let input_len = 500_000;
    let mut inputs = (0..input_len)
        .map(|_| {
            if rng.r#gen::<bool>() {
                // "Normal" class: a random, typically big, value.
                (Class::Left, Secret::init_with(|| U4096::random_mod(rng, &modulus)))
            } else {
                // "Special" class: small value.
                (Class::Right, Secret::init_with(|| U4096::ONE))
            }
        })
        .collect::<Vec<(Class, Secret<U4096>)>>();

    while let Some((class, rhs)) = inputs.pop() {
        runner.run_one(class, || secret.clone().add_assign(rhs.clone()));
    }
}
