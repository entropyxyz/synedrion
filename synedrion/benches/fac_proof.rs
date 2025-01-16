#[cfg(feature = "private_benches")]
mod bench {
    use criterion::{criterion_group, Criterion};
    use rand::SeedableRng;
    use synedrion::private_benches::*;
    use tracing_subscriber::EnvFilter;
    fn bench_fac_proof(c: &mut Criterion) {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();

        let mut group = c.benchmark_group("fac proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", fac_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", fac_proof_verify(rng));
    }

    criterion_group!(benches, bench_fac_proof);
}

// Running benchmarks without the test harness requires a main function at the top level, leading to
// this awkward setup where we get a magic criterion-main() when the feature is active and an empty
// main() when it's not.
#[cfg(feature = "private_benches")]
criterion::criterion_main!(bench::benches);
#[cfg(not(feature = "private_benches"))]
fn main() {}
