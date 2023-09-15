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

mod aff_g;
mod dec;
mod enc;
mod fac;
mod log_star;
mod mod_;
mod mul;
mod mul_star;
mod prm;
mod sch;

pub(crate) use aff_g::AffGProof;
pub(crate) use dec::DecProof;
pub(crate) use enc::EncProof;
pub(crate) use fac::FacProof;
pub(crate) use log_star::LogStarProof;
pub(crate) use mod_::ModProof;
pub(crate) use mul::MulProof;
pub(crate) use prm::PrmProof;
pub(crate) use sch::{SchCommitment, SchProof, SchSecret};
