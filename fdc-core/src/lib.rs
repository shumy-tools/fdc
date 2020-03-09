#![forbid(unsafe_code)]

mod crypto;
mod model;

pub use crate::crypto::*;
pub use crate::model::*;

// -- generic definitions --
pub type BoxError = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, BoxError>;

#[inline]
pub fn error(msg: &str) -> BoxError { From::from(msg) }

pub fn rand_string(size: usize) -> String {
  (0..size).map(|_| rand::random::<char>()).collect()
}
