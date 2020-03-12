#![forbid(unsafe_code)]

pub mod crypto;
pub mod model;

// -- generic definitions --
pub type BoxError = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, BoxError>;

#[inline]
pub fn error(msg: &str) -> BoxError { From::from(msg) }

pub fn rand(size: usize) -> Vec<u8> {
  (0..size).map(|_| rand::random::<u8>()).collect()
}
