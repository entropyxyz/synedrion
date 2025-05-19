// This module contains benchmarks for code that is not part of the public API
// and is used for testing and performance evaluation purposes.

// Benchmarks for low-level Paillier operations.
pub mod paillier;
// Benchmarks for the CGGMP'24 Zk proofs.
pub mod zk_proofs;

// Constant-time benchmarks.
pub mod secret_is_ct;
pub mod secret_signed_ct;
pub mod zk_proofs_ct;
