#![forbid(unsafe_code)]

mod crypto;

pub use crate::crypto::*;

// -- generic definitions --
pub type BoxError = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, BoxError>;

#[inline]
pub fn error(msg: &str) -> BoxError { From::from(msg) }