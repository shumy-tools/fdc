
use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use fdc_core::crypto::{SecretKey, PublicKey};
use fdc_core::model::*;

pub struct Config {
  pub values: HashMap<String, String>
}

pub trait FdpNetwork {
  fn connect(secret: &SecretKey, conf: Config) -> Self;
  fn records(&self) -> RecordChain;
}

//-----------------------------------------------------------------------------------------------------------
// RecordChain
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct RecordChain {
  pub id: String,
  pub table: String,
  
  pub lhash: Vec<u8>, // last Record hash
  pub chain: Vec<Record>
}

impl RecordChain {
  pub fn kn(&self) -> &PublicKey {
    &self.chain.last().unwrap().data.kn
  }

  pub fn new(head: Record) -> Result<Self> {
    let lhash = head.check()?;
    if head.id.is_none() {
      Err("Record is not a head type!")?
    }
    
    Ok(Self { lhash, chain: vec![head] })
  }

  pub fn push(&mut self, tail: Rn) -> Result<()> {
      let dhash = tail.check()?;

      let hprev = tail.hprev.as_ref().ok_or_else(|| error("Record is not a tail type!"))?;
      if &self.lhash != hprev {
          Err("Incorrect hash chain!")?
      }

      self.lhash = dhash;
      self.chain.push(tail);

      Ok(())
  }

  pub fn recover(&self, alpha: &CompressedRistretto) -> Result<Vec<RnFileRef>> {
      let id = self.id();
      let set = self.set();

      let mut lambda = Some(LambdaKey::new(alpha, id, set));
      let mut chain = Vec::<RnFileRef>::new();
      for rn in self.chain.iter().rev() {
          let data = rn.data.data(&lambda.as_ref().unwrap())?;
          lambda = data.lambda_prev;
          chain.push(data.file);
      }

      chain.reverse();
      Ok(chain)
  }
}
