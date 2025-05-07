use dudect_bencher::ctbench_main;
use synedrion::private_benches::{secret_signed_ct, zk_proofs_ct};

ctbench_main!(
    zk_proofs_ct::rp_commit_zero_value,
    zk_proofs_ct::rp_commit_zero_randomizer,
    secret_signed_ct::new_positive_with_constant_bound,
    secret_signed_ct::new_positive_with_constant_value
);
