//! Sigma-protocols

/*
A general note about verification:

In `verify()` methods we take both the auxiliary info (for reconstructing the challenge),
and a challenge itself (as received with the proof from the other party).
This is prescribed by Fig. 2 (ZK module for sigma-protocols).

Taking `challenge` as a parameter when we are reconstructing it anyway
may not seem necessary from the security perspective, but it provides a quick way
to detect an invalid message at the cost of an increased message size.
*/

pub(crate) mod aff_g;
pub(crate) mod enc;
pub(crate) mod fac;
pub(crate) mod log_star;
pub(crate) mod mod_;
pub(crate) mod prm;
pub(crate) mod sch;
