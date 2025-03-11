use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use crypto_bigint::{
    modular::{MontyForm, MontyParams},
    NonZero, Odd, Random, Uint, U1024, U2048, U256, U4096, U512,
};
use crypto_primes::RandomPrimeWithRng;
use rand::SeedableRng;

fn bench_pow_known_totient_512(c: &mut Criterion) {
    let mut group = c.benchmark_group("modpow, 512^1024");

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
    let p: U512 = (U256::generate_prime_with_rng(&mut rng, U256::BITS), U256::ZERO).into();
    let q: U512 = (U256::generate_prime_with_rng(&mut rng, U256::BITS), U256::ZERO).into();
    let m: U512 = p * q;
    let totient = (p - U512::ONE) * (q - U512::ONE);
    let prms = MontyParams::new_vartime(Odd::new(m).unwrap());

    group.bench_function("vanilla", |b| {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        b.iter_batched(
            || {
                let x = U512::random(&mut rng);
                let x = MontyForm::new(&x, prms);
                let exponent = U1024::random(&mut rng);
                (x, exponent)
            },
            |(x, exponent)| black_box(x.pow(&exponent)),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("known totient", |b| {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        b.iter_batched(
            || {
                let x = U512::random(&mut rng);
                let x = MontyForm::new(&x, prms);
                let exponent = U1024::random(&mut rng);
                let exponent = Uint::rem_wide_vartime(exponent.split(), &NonZero::new(totient).unwrap());
                (x, exponent)
            },
            |(x, exponent)| black_box(x.pow(&exponent)),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("known totient (not ammortized)", |b| {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        b.iter_batched(
            || {
                let x = U512::random(&mut rng);
                let x = MontyForm::new(&x, prms);
                let exponent = U1024::random(&mut rng);
                (x, exponent)
            },
            |(x, exponent)| {
                let exponent = Uint::rem_wide_vartime(exponent.split(), &NonZero::new(totient).unwrap());
                black_box(x.pow(&exponent))
            },
            BatchSize::SmallInput,
        );
    });
}

// Our production parameters use 1024-bit primes resulting in 2048-bit moduli
fn bench_pow_known_totient_2048(c: &mut Criterion) {
    let mut group = c.benchmark_group("modpow, 2048^4096");

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
    let p: U2048 = (U1024::generate_prime_with_rng(&mut rng, U1024::BITS), U1024::ZERO).into();
    let q: U2048 = (U1024::generate_prime_with_rng(&mut rng, U1024::BITS), U1024::ZERO).into();
    let m: U2048 = p * q;
    let totient = (p - U2048::ONE) * (q - U2048::ONE);
    let prms = MontyParams::new_vartime(Odd::new(m).unwrap());

    group.bench_function("vanilla", |b| {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        b.iter_batched(
            || {
                let x = U2048::random(&mut rng);
                let x = MontyForm::new(&x, prms);
                let exponent = U4096::random(&mut rng);
                (x, exponent)
            },
            |(x, exponent)| black_box(x.pow(&exponent)),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("known totient", |b| {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        b.iter_batched(
            || {
                let x = U2048::random(&mut rng);
                let x = MontyForm::new(&x, prms);
                let exponent = U4096::random(&mut rng);
                let exponent = Uint::rem_wide_vartime(exponent.split(), &NonZero::new(totient).unwrap());
                (x, exponent)
            },
            |(x, exponent)| black_box(x.pow(&exponent)),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("known totient (not ammortized)", |b| {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        b.iter_batched(
            || {
                let x = U2048::random(&mut rng);
                let x = MontyForm::new(&x, prms);
                let exponent = U4096::random(&mut rng);
                (x, exponent)
            },
            |(x, exponent)| {
                let exponent = Uint::rem_wide_vartime(exponent.split(), &NonZero::new(totient).unwrap());
                black_box(x.pow(&exponent))
            },
            BatchSize::SmallInput,
        );
    });
}
criterion_group!(benches, bench_pow_known_totient_512, bench_pow_known_totient_2048);

criterion_main!(benches);
