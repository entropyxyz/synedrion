#[cfg(feature = "private_benches")]
mod bench {
    use criterion::{criterion_group, Criterion};
    use rand::SeedableRng;
    use synedrion::private_benches::*;
    use tracing_subscriber::EnvFilter;
    fn bench_fac(c: &mut Criterion) {
        use fac_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();

        let mut group = c.benchmark_group("fac proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", fac_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", fac_proof_verify(rng));
    }

    fn bench_aff_g(c: &mut Criterion) {
        use aff_g_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let mut group = c.benchmark_group("AffG proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", aff_g_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", aff_g_proof_verify(rng));
    }

    fn bench_dec(c: &mut Criterion) {
        use dec_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let mut group = c.benchmark_group("Dec proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", dec_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", dec_proof_verify(rng));
    }

    fn bench_enc(c: &mut Criterion) {
        use enc_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let mut group = c.benchmark_group("Enc proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", enc_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", enc_proof_verify(rng));
    }

    fn bench_log_star(c: &mut Criterion) {
        use log_star_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let mut group = c.benchmark_group("LogStar proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", log_star_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", log_star_proof_verify(rng));
    }

    fn bench_paillier_blum_modulus(c: &mut Criterion) {
        use paillier_blum_modulus_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let mut group = c.benchmark_group("Paillier-Blum modulus proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", paillier_blum_modulus_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", paillier_blum_modulus_proof_verify(rng));
    }

    fn bench_mul_star(c: &mut Criterion) {
        use mul_star_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let mut group = c.benchmark_group("MulStar proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", mul_star_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", mul_star_proof_verify(rng));
    }

    fn bench_paillier_mul(c: &mut Criterion) {
        use paillier_mul_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let mut group = c.benchmark_group("Paillier multiplication proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", paillier_mul_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", paillier_mul_proof_verify(rng));
    }

    criterion_group!(
        benches,
        bench_fac,
        bench_aff_g,
        bench_dec,
        bench_enc,
        bench_log_star,
        bench_paillier_blum_modulus,
        bench_mul_star,
        bench_paillier_mul,
    );
}

// Running benchmarks without the test harness requires a main function at the top level, leading to
// this awkward setup where we get a magic criterion-main() when the feature is active and an empty
// main() when it's not.
#[cfg(feature = "private_benches")]
criterion::criterion_main!(bench::benches);
#[cfg(not(feature = "private_benches"))]
fn main() {}
