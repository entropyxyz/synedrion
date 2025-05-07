use dudect_bencher::rand::Rng;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use synedrion::private_benches::zk_proofs_ct;

// Crate the main function to include the bench for vec_eq
ctbench_main!(
    zk_proofs_ct::rp_commit_zero_value,
    zk_proofs_ct::rp_commit_zero_randomizer
);
