#![cfg_attr(feature = "unstable", feature(test))]
#![doc(html_no_source)]

//! SamEncrypt provides a set of cryptographic primitives for building a
//! single-hop proxy self re-encryption scheme.
//!
//! The implementation is based on the original paper by Selvi et al. entitled
//! [Sharing of Encrypted files in Blockchain Made Simpler](https://eprint.iacr.org/2019/418.pdf)  
//!
//! Start exploring the [Api documentation](api/index.html)

pub mod core;
pub mod elliptic_curve;
pub mod hashing;
pub mod internals;
pub mod test_utils;
