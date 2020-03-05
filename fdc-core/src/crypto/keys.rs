use clear_on_drop::clear::Clear;

use std::fmt::{Debug, Formatter};
use serde::{Serialize, Deserialize};
use core::ops::{Neg, Add, Mul, Sub, AddAssign, MulAssign, SubAssign};

use digest::generic_array::typenum::U64;
use digest::Digest;

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;

fn rand_scalar() -> Scalar {
  use rand::prelude::*;
  let mut rng = rand::thread_rng();

  let mut scalar_bytes = [0u8; 64];
  rng.fill_bytes(&mut scalar_bytes);
  Scalar::from_bytes_mod_order_wide(&scalar_bytes)
}

pub const G: PublicKey = PublicKey(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT);

//-----------------------------------------------------------------------------------------------------------
// SecretKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SecretKey(Scalar);

impl SecretKey {
  pub fn rand() -> SecretKey {
    SecretKey(rand_scalar())
  }

  pub fn zero() -> SecretKey {
    SecretKey(Scalar::zero())
  }

  pub fn one() -> SecretKey {
    SecretKey(Scalar::one())
  }

  pub fn invert(&self) -> SecretKey {
    SecretKey(self.0.invert())
  }

  pub fn encode(&self) -> String {
    base64::encode(&self.as_bytes())
  }

  pub fn decode(value: &str) -> SecretKey {
    let data = base64::decode(value).expect("Unable to decode base64 input!");
    let mut bytes: [u8; 32] = Default::default();
    bytes.copy_from_slice(&data[0..32]);

    SecretKey(Scalar::from_canonical_bytes(bytes).expect("Unable to decode Scalar!"))
  }

  pub fn as_bytes(&self) -> &[u8; 32] {
    self.0.as_bytes()
  }

  pub fn from_hash<D>(hash: D) -> SecretKey where D: Digest<OutputSize = U64> {
    let mut output = [0u8; 64];
    output.copy_from_slice(hash.result().as_slice());
    SecretKey(Scalar::from_bytes_mod_order_wide(&output))
  }
}

impl Debug for SecretKey {
  fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
    fmt.debug_tuple("PublicKey")
      .field(&self.encode())
      .finish()
  }
}

impl Drop for SecretKey {
  fn drop(&mut self) {
    self.0.clear();
  }
}

impl From<u32> for SecretKey {
  fn from(x: u32) -> SecretKey {
    SecretKey(Scalar::from(x))
  }
}

impl From<u64> for SecretKey {
  fn from(x: u64) -> SecretKey {
    SecretKey(Scalar::from(x))
  }
}

neg_variant!(Type = SecretKey);
impl<'a> Neg for &'a SecretKey {
  type Output = SecretKey;
  fn neg(self) -> SecretKey {
    SecretKey(-self.0)
  }
}

add_variants!(LHS = SecretKey, RHS = SecretKey, Output = SecretKey);
impl<'a, 'b> Add<&'b SecretKey> for &'a SecretKey {
  type Output = SecretKey;
  fn add(self, rhs: &'b SecretKey) -> SecretKey {
    SecretKey(self.0 + rhs.0)
  }
}

add_assign_variant!(Type = SecretKey);
impl<'a> AddAssign<&'a SecretKey> for SecretKey {
  fn add_assign(&mut self, rhs: &'a SecretKey) {
    self.0 = self.0 + rhs.0;
  }
}

sub_variants!(LHS = SecretKey, RHS = SecretKey, Output = SecretKey);
impl<'a, 'b> Sub<&'b SecretKey> for &'a SecretKey {
  type Output = SecretKey;
  fn sub(self, rhs: &'b SecretKey) -> SecretKey {
    SecretKey(self.0 - rhs.0)
  }
}

sub_assign_variant!(Type = SecretKey);
impl<'a> SubAssign<&'a SecretKey> for SecretKey {
  fn sub_assign(&mut self, rhs: &'a SecretKey) {
    self.0 = self.0 - rhs.0;
  }
}

mul_variants!(LHS = SecretKey, RHS = SecretKey, Output = SecretKey);
impl<'a, 'b> Mul<&'b SecretKey> for &'a SecretKey {
  type Output = SecretKey;
  fn mul(self, rhs: &'b SecretKey) -> SecretKey {
    SecretKey(self.0 * rhs.0)
  }
}

mul_assign_variant!(Type = SecretKey);
impl<'a> MulAssign<&'a SecretKey> for SecretKey {
  fn mul_assign(&mut self, rhs: &'a SecretKey) {
    self.0 = self.0 * rhs.0;
  }
}

mul_variants!(LHS = SecretKey, RHS = PublicKey, Output = PublicKey; Commutative = PublicKey);
impl<'a, 'b> Mul<&'b PublicKey> for &'a SecretKey {
  type Output = PublicKey;
  fn mul(self, rhs: &'b PublicKey) -> PublicKey {
    PublicKey(self.0 * &rhs.0)
  }
}

//-----------------------------------------------------------------------------------------------------------
// PublicKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq)]
pub struct PublicKey(RistrettoPoint);

impl PublicKey {
  pub fn zero() -> PublicKey {
    PublicKey(RistrettoPoint::default())
  }

  pub fn encode(&self) -> String {
    base64::encode(&self.to_bytes())
  }

  pub fn decode(value: &str) -> PublicKey {
    let data = base64::decode(value).expect("Unable to decode base64 input!");
    let point = CompressedRistretto::from_slice(&data);
    
    PublicKey(point.decompress().expect("Unable to decompress RistrettoPoint!"))
  }

  pub fn to_bytes(&self) -> [u8; 32] {
    let compressed = self.0.compress();
    compressed.to_bytes()
  }
}

impl Debug for PublicKey {
  fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
    fmt.debug_tuple("PublicKey")
      .field(&self.encode())
      .finish()
  }
}

add_variants!(LHS = PublicKey, RHS = PublicKey, Output = PublicKey);
impl<'a, 'b> Add<&'b PublicKey> for &'a PublicKey {
  type Output = PublicKey;
  fn add(self, rhs: &'b PublicKey) -> PublicKey {
    PublicKey(self.0 + rhs.0)
  }
}

add_assign_variant!(Type = PublicKey);
impl<'a> AddAssign<&'a PublicKey> for PublicKey {
  fn add_assign(&mut self, rhs: &'a PublicKey) {
    self.0 = self.0 + rhs.0;
  }
}

sub_variants!(LHS = PublicKey, RHS = PublicKey, Output = PublicKey);
impl<'a, 'b> Sub<&'b PublicKey> for &'a PublicKey {
  type Output = PublicKey;
  fn sub(self, rhs: &'b PublicKey) -> PublicKey {
    PublicKey(self.0 - rhs.0)
  }
}

sub_assign_variant!(Type = PublicKey);
impl<'a> SubAssign<&'a PublicKey> for PublicKey {
  fn sub_assign(&mut self, rhs: &'a PublicKey) {
    self.0 = self.0 - rhs.0;
  }
}

//-----------------------------------------------------------------------------------------------------------
// KeyPair
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct KeyPair {
  pub secret: SecretKey,
  pub key: PublicKey
}

impl KeyPair {
  pub fn rand() -> Self {
    let secret = SecretKey(rand_scalar());
    let key = &secret * G;
    Self { secret, key }
  }
}