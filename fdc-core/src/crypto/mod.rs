mod macros;

mod keys;
mod shares;
mod signatures;

pub use keys::*;
pub use shares::*;
pub use signatures::*;

pub fn rand_string(size: usize) -> String {
  (0..size).map(|_| rand::random::<char>()).collect()
}
