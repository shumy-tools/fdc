#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};

use crate::{KeyPair, PublicKey, SecretKey, G};
use sha2::{Digest, Sha512};

//-----------------------------------------------------------------------------------------------------------
// Schnorr's signature
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct Signature {
  pub c: SecretKey,
  pub p: SecretKey,
}

impl Signature {
  pub fn sign(kp: &KeyPair, dhash: &[u8]) -> Self {
    let hasher = Sha512::new()
      .chain(kp.secret.as_bytes())
      .chain(dhash);

    let m = SecretKey::from_hash(hasher);
    let M = &m * G;

    let hasher = Sha512::new()
      .chain(kp.key.to_bytes())
      .chain(M.to_bytes())
      .chain(dhash);

    let c = SecretKey::from_hash(hasher);
    let p = m - &c * &kp.secret;

    Self { c, p }
  }

  pub fn verify(&self, key: &PublicKey, dhash: &[u8]) -> bool {
    let M = &self.c * key + &self.p * G;

    let hasher = Sha512::new()
      .chain(key.to_bytes())
      .chain(M.to_bytes())
      .chain(dhash);

    let c = SecretKey::from_hash(hasher);
    c == self.c
  }
}

//-----------------------------------------------------------------------------------------------------------
// Schnorr's signature with PublicKey (Extended Signature)
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct ExtSignature {
  pub sig: Signature,
  pub key: PublicKey,
}

impl ExtSignature {
  pub fn sign(kp: &KeyPair, dhash: &[u8]) -> Self {
    let sig = Signature::sign(kp, dhash);
    Self { sig, key: kp.key }
  }

  pub fn verify(&self, dhash: &[u8]) -> bool {
    self.sig.verify(&self.key, dhash)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::rand_string;

  #[test]
  fn test_correct() {
    let kpa = KeyPair::rand();

    let d0 = rand_string(10);
    let d1 = rand_string(10);

    let dhash = Sha512::new()
      .chain(d0.as_bytes())
      .chain(d1.as_bytes())
      .result();

    let sig = ExtSignature::sign(&kpa, dhash.as_slice());
    assert!(sig.verify(dhash.as_slice()) == true);
  }

  #[test]
  fn test_incorrect() {
    let kpa = KeyPair::rand();

    let d0 = rand_string(10);
    let d1 = rand_string(10);
    let d2 = rand_string(10);

    let dhash1 = Sha512::new()
      .chain(d0.as_bytes())
      .chain(d1.as_bytes())
      .result();

    let sig = ExtSignature::sign(&kpa, dhash1.as_slice());

    let dhash2 = Sha512::new()
      .chain(d0.as_bytes())
      .chain(d2.as_bytes())
      .result();

    assert!(sig.verify(dhash2.as_slice()) == false);
  }
}
