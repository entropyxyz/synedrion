#[cfg(feature = "private_benches")]
mod bench {
    use criterion::{criterion_group, Criterion};
    use rand::SeedableRng;
    use synedrion::private_benches::*;
    use tracing_subscriber::EnvFilter;

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

    fn bench_fac(c: &mut Criterion) {
        use fac_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();

        let mut group = c.benchmark_group("Fac proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", fac_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", fac_proof_verify(rng));
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

    fn bench_prm(c: &mut Criterion) {
        use prm_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let mut group = c.benchmark_group("Pedersen Ring params (prm) proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", prm_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", prm_proof_verify(rng));
    }

    fn bench_sch(c: &mut Criterion) {
        use sch_proof::*;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let mut group = c.benchmark_group("Schnorr (sch) proof");
        group.sample_size(10);

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("prove", sch_proof_prove(rng));

        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
        group.bench_function("verify", sch_proof_verify(rng));
    }

    criterion_group!(
        benches,
        bench_fac,
        bench_aff_g,
        bench_dec,
        bench_paillier_blum_modulus,
        bench_prm,
        bench_sch
    );
}

criterion::criterion_main!(bench::benches);
