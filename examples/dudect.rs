use dudect_bencher::ctbench_main_with_seeds;
use synedrion::private_benches::{secret_is_ct, secret_signed_ct, zk_proofs_ct};

ctbench_main_with_seeds!(
    (zk_proofs_ct::rp_commit_both, Some(0x3d8068bdbf839043)),
    (zk_proofs_ct::rp_commit_zero_value, None),
    (zk_proofs_ct::rp_commit_zero_randomizer, None),
    (secret_signed_ct::new_positive_with_constant_bound, None),
    (secret_signed_ct::new_positive_with_constant_value, None),
    (secret_is_ct::init_with, None),
    (secret_is_ct::wrapping_add, None),
    (secret_is_ct::wrapping_add_uints, Some(0x4199c85218633e77)),
    (secret_is_ct::add_assign, None),
    (secret_is_ct::add_assign_uints, Some(0x3d0bd611749f5367))
);
