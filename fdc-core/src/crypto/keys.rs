use clear_on_drop::clear::Clear;

use std::fmt::{Debug, Formatter};
use serde::{Serialize, Deserialize};
use core::ops::{Neg, Add, Mul, Sub, AddAssign, MulAssign, SubAssign};

use sha2::Sha512;
use digest::generic_array::typenum::U64;
use digest::Digest;

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;

use crate::{error, Result};

fn rand_scalar() -> Scalar {
  use rand::prelude::*;
  let mut rng = rand::thread_rng();

  let mut scalar_bytes = [0u8; 64];
  rng.fill_bytes(&mut scalar_bytes);
  Scalar::from_bytes_mod_order_wide(&scalar_bytes)
}

pub const G: PublicKey = PublicKey(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT);

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum KeySize { S128, S192, S256, S512 }

impl KeySize {
  pub fn size(&self) -> usize {
    match self {
      KeySize::S128 => 128,
      KeySize::S192 => 192,
      KeySize::S256 => 256,
      KeySize::S512 => 512
    }
  }
}

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

  pub fn decode(value: &str) -> Result<SecretKey> {
    let data = base64::decode(value).map_err(|_| error("SecretKey: Unable to decode base64 input!"))?;
    if data.len() < 32 {
      Err("SecretKey: Decoded value is less than 32 bytes!")?
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[0..32]);

    let secret = Scalar::from_canonical_bytes(bytes)
      .ok_or_else(|| error("SecretKey: Unable to decode Scalar!"))?;
    
    Ok(SecretKey(secret))
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
    fmt.debug_tuple("SecretKey")
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

  pub fn decode(value: &str) -> Result<PublicKey> {
    let data = base64::decode(value).map_err(|_| error("PublicKey: Unable to decode base64 input!"))?;
    if data.len() < 32 {
      Err("PublicKey: Decoded value is less than 32 bytes!")?
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[0..32]);

    let key = CompressedRistretto(bytes).decompress()
      .ok_or_else(|| error("PublicKey: Unable to decompress RistrettoPoint!"))?;
    
    Ok(PublicKey(key))
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
    let secret = SecretKey::rand();
    let key = &secret * G;

    Self { secret, key }
  }

  pub fn load(secret: &str, key: &str) -> Result<Self> {
    let secret = SecretKey::decode(secret)?;
    let key = PublicKey::decode(key)?;

    Ok(Self { secret, key })
  }
}

//-----------------------------------------------------------------------------------------------------------
// LambdaKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LambdaKey(Vec<u8>);

impl Drop for LambdaKey {
  fn drop(&mut self) {
    self.0.clear();
  }
}

impl LambdaKey {
  pub fn new(alpha: &PublicKey, salt: &[u8]) -> Self {
    let key = Sha512::new()
      .chain(alpha.to_bytes())
      .chain(salt)
      .result().to_vec();
    
    Self(key)
  }

  pub fn k128(&self) -> &[u8; 16] {
    arrayref::array_ref!(self.0, 0, 16)
  }

  pub fn k192(&self) -> &[u8; 24] {
    arrayref::array_ref!(self.0, 0, 24)
  }

  pub fn k256(&self) -> &[u8; 32] {
    arrayref::array_ref!(self.0, 0, 32)
  }

  pub fn k512(&self) -> &[u8; 64] {
    arrayref::array_ref!(self.0, 0, 64)
  }
}