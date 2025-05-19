use core::ops::{Add, AddAssign};

use crypto_bigint::{NonZero, Random, RandomMod, WrappingAdd, U4096};
use dudect_bencher::{BenchRng, Class, CtRunner};
use rand::Rng;

use crate::tools::Secret;

/// Is `Secret::init_with` constant time? This actually tests that `Box::new` is CT (which it isn't).
pub fn init_with(runner: &mut CtRunner, rng: &mut BenchRng) {
    let modulus = NonZero::new(U4096::ONE << 4095).unwrap();

    // Need ~300M-600M iterations to get a clear reading, but that takes a long time and consumes a lot of memory.
    // Run with `--continous`.
    let input_len = 10_000_000;
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

/// Is `Secret::wrapping_add` constant time? (It's not)
pub fn wrapping_add(runner: &mut CtRunner, rng: &mut BenchRng) {
    let modulus = NonZero::new(U4096::MAX.shr_vartime(3)).unwrap();
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

/// Is `Uint::wrapping_add` constant time?
pub fn wrapping_add_uints(runner: &mut CtRunner, rng: &mut BenchRng) {
    let secret = U4096::MAX - U4096::from_u8(9);
    let input_len = 10_000_000;
    let mut inputs = (0..input_len)
        .map(|_| {
            if rng.r#gen::<bool>() {
                (Class::Left, U4096::random(rng))
            } else {
                (Class::Right, U4096::ONE)
            }
        })
        .collect::<Vec<(Class, U4096)>>();
    while let Some((class, rhs)) = inputs.pop() {
        runner.run_one(class, || secret.wrapping_add(&rhs));
    }
}

/// Is `Secret::add_assign` constant time? (It's not)
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

/// When add_assign-ing raw uint's we're much closer to being CT than when using the secret
/// type. Likely it's the allocator that messes up the party again.
pub fn add_assign_uints(runner: &mut CtRunner, rng: &mut BenchRng) {
    let secret = U4096::MAX.shr_vartime(2048) - U4096::from_u8(2);
    let input_len = 10_000_000;
    let mut inputs = (0..input_len)
        .map(|_| {
            if rng.r#gen::<bool>() {
                // "Normal" class: a random, typically big, value.
                (Class::Left, U4096::random(rng).shr_vartime(2048))
            } else {
                // "Special" class: small value.
                (Class::Right, U4096::ONE)
            }
        })
        .collect::<Vec<(Class, U4096)>>();

    while let Some((class, rhs)) = inputs.pop() {
        runner.run_one(class, || secret.clone().add_assign(&rhs));
    }
}
