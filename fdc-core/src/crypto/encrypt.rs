use crypto::aes::KeySize;
use crypto::aesni::{AesNiEncryptor, AesNiDecryptor};
use aesstream::{AesWriter, AesReader};

use std::io::{Read, Write};

use crate::Result;
use crate::crypto::LambdaKey;

//-----------------------------------------------------------------------------------------------------------
// Supported encryption schemes
//-----------------------------------------------------------------------------------------------------------
#[derive(Copy, Clone)]
pub enum EncryptScheme {
  AesCbc128, AesCbc192, AesCbc256
}

//-----------------------------------------------------------------------------------------------------------
// encryptor / decryptor
//-----------------------------------------------------------------------------------------------------------
pub fn encryptor<'a, W: Write + 'a>(scheme: EncryptScheme, key: &LambdaKey, to: W) -> Result<Box<dyn Write + 'a>> {
  let engine = match scheme {
    EncryptScheme::AesCbc128 => {
      let encryptor = AesNiEncryptor::new(KeySize::KeySize128, key.k128());
      Box::new(AesWriter::new(to, encryptor)?)
    },
    EncryptScheme::AesCbc192 => {
      let encryptor = AesNiEncryptor::new(KeySize::KeySize192, key.k192());
      Box::new(AesWriter::new(to, encryptor)?)
    },
    EncryptScheme::AesCbc256 => {
      let encryptor = AesNiEncryptor::new(KeySize::KeySize256, key.k256());
      Box::new(AesWriter::new(to, encryptor)?)
    }
  };

  Ok(engine)
}

pub fn decryptor<'a, R: Read + 'a>(scheme: EncryptScheme, key: &LambdaKey, from: R) -> Result<Box<dyn Read + 'a>> {
  let engine = match scheme {
    EncryptScheme::AesCbc128 => {
      let decryptor = AesNiDecryptor::new(KeySize::KeySize128, key.k128());
      Box::new(AesReader::new(from, decryptor)?)
    },
    EncryptScheme::AesCbc192 => {
      let decryptor = AesNiDecryptor::new(KeySize::KeySize192, key.k192());
      Box::new(AesReader::new(from, decryptor)?)
    },
    EncryptScheme::AesCbc256 => {
      let decryptor = AesNiDecryptor::new(KeySize::KeySize256, key.k256());
      Box::new(AesReader::new(from, decryptor)?)
    }
  };

  Ok(engine)
}