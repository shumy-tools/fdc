use sha2::{Digest, Sha512};
use serde::{Serialize, Deserialize};
use std::io::{Read, Write};

use crate::{rand, Result};
use crate::crypto::*;

pub fn salt(id: &str, table: &str) -> Vec<u8> {
  let dhash = Sha512::new()
    .chain(id)
    .chain(table)
    .result();

  dhash.to_vec()
}

//-----------------------------------------------------------------------------------------------------------
// RDataRef
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct RDataRef {
  pub ksize: KeySize,
  pub dn: Vec<u8>,
  pub hfile: Vec<u8>
}

//-----------------------------------------------------------------------------------------------------------
// RData
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct RData {
  pub lprev: Option<LambdaKey>,
  pub dref: RDataRef
}

impl RData {
  pub fn head(ksize: KeySize, hfile: &[u8]) -> Self {
    let dn = rand(ksize.size());
    Self { lprev: None, dref: RDataRef { ksize: KeySize::S128, dn, hfile: hfile.into() } }
  }

  pub fn tail(ksize: KeySize, lprev: LambdaKey, hfile: &[u8]) -> Self {
    let dn = rand(ksize.size());
    Self { lprev: Some(lprev), dref: RDataRef { ksize: KeySize::S128, dn, hfile: hfile.into() } }
  }
}

//-----------------------------------------------------------------------------------------------------------
// REncData
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct REncData {
  pub kn: PublicKey,
  ciphertext: Vec<u8>
}

impl REncData {
  fn new(ekey: &PublicKey, salt: &[u8], rd: &RData) -> (LambdaKey, Self) {
    let k = SecretKey::rand();
    let alpha = &k * ekey;
    let lambda = LambdaKey::new(&alpha, salt);

    // E_{lambda} [lprev, dn, hfile]
    let from = bincode::serialize(rd).unwrap();
    let mut to = Vec::new();
    {
      // encryption should not fail
      let mut ecryptor = encryptor(EncryptScheme::AesCbc128, &lambda, &mut to).unwrap();
      ecryptor.write_all(from.as_slice()).unwrap();
    }

    (lambda, Self { kn: (k * G), ciphertext: to })
  }

  fn data(&self, lambda: &LambdaKey) -> Result<RData> {
    // D_{lambda} [lprev, dn, hfile]
    let mut to = Vec::new();
    {
      let mut decryptor = decryptor(EncryptScheme::AesCbc128, lambda, self.ciphertext.as_slice())?;
      decryptor.read_to_end(&mut to)?;
    }

    let cd: RData = bincode::deserialize(&to)?;
    Ok(cd)
  }
}

//-----------------------------------------------------------------------------------------------------------
// Record
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct Record {
  pub hprev: Vec<u8>,
  data: REncData,
  sig: ExtSignature
}

impl Record {
  pub fn owner(&self) -> &PublicKey {
    &self.sig.key
  }

  pub fn data(&self, lambda: &LambdaKey) -> Result<RData> {
    self.data.data(lambda)
  }

  pub fn head(keyp: &KeyPair, ekey: &PublicKey, salt: &[u8], rd: RData) -> (LambdaKey, Self) {
    Record::create(keyp, ekey, salt, salt, rd)
  }

  pub fn tail(keyp: &KeyPair, ekey: &PublicKey, hprev: &[u8], salt: &[u8], rd: RData) -> (LambdaKey, Self) {
    Record::create(keyp, ekey, hprev, salt, rd)
  }

  pub fn check(&self) -> Result<Vec<u8>> {
    let dhash = Record::hash(&self.hprev, &self.data);
    if !self.sig.verify(&dhash) {
      Err("Invalid record signature!")?
    }

    Ok(dhash)
  }

  pub fn hash(hprev: &[u8], red: &REncData) -> Vec<u8> {
    let b_data = bincode::serialize(red).unwrap();
    let dhash = Sha512::new()
      .chain(hprev)
      .chain(b_data)
      .result();

    dhash.to_vec()
  }

  fn create(keyp: &KeyPair, ekey: &PublicKey, hprev: &[u8], salt: &[u8], rd: RData) -> (LambdaKey, Self) {
    let (lambda, data) = REncData::new(ekey, salt, &rd);
    let dhash = Record::hash(hprev, &data);
    
    let sig = ExtSignature::sign(keyp, dhash.as_slice());
    (lambda, Self { hprev: hprev.to_vec(), data, sig })
  }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_write_load() {
      let salt = salt("subject-id", "table-id");

      let ekp = KeyPair::rand(); // master key-pair
      let skp = KeyPair::rand(); // source key-pair

      let rd1 = RData::head(KeySize::S128, b"data-url");
      let (_, r1) = Record::head(&skp, &ekp.key, &salt, rd1.clone());
      assert!(r1.check().is_ok());

      let alpha = ekp.secret * &r1.data.kn;
      let lambda = LambdaKey::new(&alpha, &salt);
      let rd2 = r1.data(&lambda).unwrap();
      assert!(rd1 == rd2);
    }
  }