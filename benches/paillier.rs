use criterion::{criterion_group, criterion_main};
use synedrion::private_benches::paillier;

criterion_group!(benches, paillier::bench_paillier);
criterion_main!(benches);
