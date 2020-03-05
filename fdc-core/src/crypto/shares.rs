#![allow(non_snake_case)]

use core::ops::{Add, Mul, Sub};
use serde::{Deserialize, Serialize};

use crate::crypto::{PublicKey, SecretKey};

pub trait Evaluate {
  type Output;
  fn evaluate(&self, x: &SecretKey) -> Self::Output;
}

pub trait Degree {
  fn degree(&self) -> usize;
}

//-----------------------------------------------------------------------------------------------------------
// Share
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Share {
  pub i: u32,
  pub yi: SecretKey,
}

add_variants!(LHS = Share, RHS = Share, Output = Share);
impl<'a, 'b> Add<&'b Share> for &'a Share {
  type Output = Share;
  fn add(self, rhs: &'b Share) -> Share {
    assert!(self.i == rhs.i);
    Share { i: self.i, yi: &self.yi + &rhs.yi }
  }
}

add_variants!(LHS = Share, RHS = SecretKey, Output = Share; Commutative = Share);
impl<'a, 'b> Add<&'b SecretKey> for &'a Share {
  type Output = Share;
  fn add(self, rhs: &'b SecretKey) -> Share {
    Share { i: self.i, yi: &self.yi + rhs }
  }
}

sub_variants!(LHS = Share, RHS = Share, Output = Share);
impl<'a, 'b> Sub<&'b Share> for &'a Share {
  type Output = Share;
  fn sub(self, rhs: &'b Share) -> Share {
    assert!(self.i == rhs.i);
    Share { i: self.i, yi: &self.yi - &rhs.yi }
  }
}

sub_variants!(LHS = Share, RHS = SecretKey, Output = Share);
impl<'a, 'b> Sub<&'b SecretKey> for &'a Share {
  type Output = Share;
  fn sub(self, rhs: &'b SecretKey) -> Share {
    Share { i: self.i, yi: &self.yi - rhs }
  }
}

mul_variants!(LHS = Share, RHS = SecretKey, Output = Share; Commutative = Share);
impl<'a, 'b> Mul<&'b SecretKey> for &'a Share {
  type Output = Share;
  fn mul(self, rhs: &'b SecretKey) -> Share {
    Share { i: self.i, yi: &self.yi * rhs }
  }
}

mul_variants!(LHS = Share, RHS = PublicKey, Output = PublicShare; Commutative = PublicShare);
impl<'a, 'b> Mul<&'b PublicKey> for &'a Share {
  type Output = PublicShare;
  fn mul(self, rhs: &'b PublicKey) -> PublicShare {
    PublicShare { i: self.i, Yi: &self.yi * rhs }
  }
}

//-----------------------------------------------------------------------------------------------------------
// PublicShare
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PublicShare {
  pub i: u32,
  pub Yi: PublicKey,
}

add_variants!(LHS = PublicShare, RHS = PublicShare, Output = PublicShare);
impl<'a, 'b> Add<&'b PublicShare> for &'a PublicShare {
  type Output = PublicShare;
  fn add(self, rhs: &'b PublicShare) -> PublicShare {
    assert!(self.i == rhs.i);
    PublicShare { i: self.i, Yi: &self.Yi + &rhs.Yi }
  }
}

add_variants!(LHS = PublicShare, RHS = PublicKey, Output = PublicShare; Commutative = PublicShare);
impl<'a, 'b> Add<&'b PublicKey> for &'a PublicShare {
  type Output = PublicShare;
  fn add(self, rhs: &'b PublicKey) -> PublicShare {
    PublicShare { i: self.i, Yi: self.Yi + rhs }
  }
}

sub_variants!(LHS = PublicShare, RHS = PublicShare, Output = PublicShare);
impl<'a, 'b> Sub<&'b PublicShare> for &'a PublicShare {
  type Output = PublicShare;
  fn sub(self, rhs: &'b PublicShare) -> PublicShare {
    assert!(self.i == rhs.i);
    PublicShare { i: self.i, Yi: &self.Yi - &rhs.Yi }
  }
}

sub_variants!(LHS = PublicShare, RHS = PublicKey, Output = PublicShare);
impl<'a, 'b> Sub<&'b PublicKey> for &'a PublicShare {
  type Output = PublicShare;
  fn sub(self, rhs: &'b PublicKey) -> PublicShare {
    PublicShare { i: self.i, Yi: self.Yi - rhs }
  }
}

mul_variants!(LHS = PublicShare, RHS = SecretKey, Output = PublicShare; Commutative = PublicShare);
impl<'a, 'b> Mul<&'b SecretKey> for &'a PublicShare {
  type Output = PublicShare;
  fn mul(self, rhs: &'b SecretKey) -> PublicShare {
    PublicShare { i: self.i, Yi: self.Yi * rhs }
  }
}

//-----------------------------------------------------------------------------------------------------------
// ShareVector
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ShareVector(pub Vec<Share>);

impl ShareVector {
  pub fn recover(&self) -> SecretKey {
    let range = self.0.iter()
      .map(|s| SecretKey::from(s.i))
      .collect::<Vec<_>>();

    let mut acc = SecretKey::zero();
    for (i, item) in self.0.iter().enumerate() {
      acc += Polynomial::l_i(&range, i) * &item.yi;
    }

    acc
  }
}

mul_variants!(LHS = ShareVector, RHS = PublicKey, Output = PublicShareVector; Commutative = PublicShareVector);
impl<'a, 'b> Mul<&'b PublicKey> for &'a ShareVector {
  type Output = PublicShareVector;
  fn mul(self, rhs: &'b PublicKey) -> PublicShareVector {
    let res: Vec<PublicShare> = self.0.iter().map(|s| s * rhs).collect();
    PublicShareVector(res)
  }
}

//-----------------------------------------------------------------------------------------------------------
// PublicShareVector
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PublicShareVector(pub Vec<PublicShare>);

impl PublicShareVector {
  pub fn recover(&self) -> PublicKey {
    let range = self.0.iter()
      .map(|s| SecretKey::from(s.i))
      .collect::<Vec<_>>();

    let mut acc = PublicKey::zero();
    for (i, item) in self.0.iter().enumerate() {
      acc += Polynomial::l_i(&range, i) * item.Yi;
    }

    acc
  }
}

//-----------------------------------------------------------------------------------------------------------
// Polynomial
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Polynomial {
  pub a: Vec<SecretKey>
}

mul_variants!(LHS = Polynomial, RHS = SecretKey, Output = Polynomial; Commutative = Polynomial);
impl<'a, 'b> Mul<&'b SecretKey> for &'a Polynomial {
  type Output = Polynomial;
  fn mul(self, rhs: &'b SecretKey) -> Polynomial {
    Polynomial { a: self.a.iter().map(|ak| ak * rhs).collect::<Vec<SecretKey>>() }
  }
}

mul_variants!(LHS = Polynomial, RHS = PublicKey, Output = PublicPolynomial; Commutative = PublicPolynomial);
impl<'a, 'b> Mul<&'b PublicKey> for &'a Polynomial {
  type Output = PublicPolynomial;
  fn mul(self, rhs: &'b PublicKey) -> PublicPolynomial {
    PublicPolynomial { A: self.a.iter().map(|ak| ak * rhs).collect::<Vec<_>>() }
  }
}

impl Polynomial {
  pub fn rand(secret: SecretKey, degree: usize) -> Self {
    let mut coefs = vec![secret];
    let rnd_coefs: Vec<SecretKey> = (0..degree).map(|_| SecretKey::rand()).collect();
    coefs.extend(rnd_coefs);

    Polynomial { a: coefs }
  }

  pub fn shares(&self, n: usize) -> ShareVector {
    let mut shares = Vec::<Share>::with_capacity(n);
    for j in 1..=n {
      let x = SecretKey::from(j as u64);
      let share = Share { i: j as u32, yi: self.evaluate(&x) };
      shares.push(share);
    }

    ShareVector(shares)
  }

  fn l_i(range: &[SecretKey], i: usize) -> SecretKey {
    let mut num = SecretKey::one();
    let mut denum = SecretKey::one();
    for j in 0..range.len() {
      if j != i {
        num *= &range[j];
        denum *= &range[j] - &range[i];
      }
    }

    num * denum.invert()
  }
}

impl Evaluate for Polynomial {
  type Output = SecretKey;
  fn evaluate(&self, x: &SecretKey) -> SecretKey {
    // evaluate using Horner's rule
    let mut rev = self.a.iter().rev();
    let head = rev.next().unwrap().clone();

    rev.fold(head, |partial, coef| partial * x + coef)
  }
}

impl Degree for Polynomial {
  fn degree(&self) -> usize {
    self.a.len() - 1
  }
}

//-----------------------------------------------------------------------------------------------------------
// PublicPolynomial
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PublicPolynomial {
  pub A: Vec<PublicKey>,
}

mul_variants!(LHS = PublicPolynomial, RHS = SecretKey, Output = PublicPolynomial; Commutative = PublicPolynomial);
impl<'a, 'b> Mul<&'b SecretKey> for &'a PublicPolynomial {
  type Output = PublicPolynomial;
  fn mul(self, rhs: &'b SecretKey) -> PublicPolynomial {
    PublicPolynomial { A: self.A.iter().map(|Ak| Ak * rhs).collect::<Vec<_>>() }
  }
}

impl PublicPolynomial {
  pub fn verify(&self, share: &PublicShare) -> bool {
    let x = SecretKey::from(u64::from(share.i));
    share.Yi == self.evaluate(&x)
  }
}

impl Evaluate for PublicPolynomial {
  type Output = PublicKey;
  fn evaluate(&self, x: &SecretKey) -> PublicKey {
    // evaluate using Horner's rule
    let mut rev = self.A.iter().rev();
    let head = *rev.next().unwrap();

    rev.fold(head, |partial, coef| partial * x + coef)
  }
}

impl Degree for PublicPolynomial {
  fn degree(&self) -> usize {
    self.A.len() - 1
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::crypto::G;

  #[test]
  fn test_reconstruct() {
    let threshold = 16;
    let parties = 3 * threshold + 1;

    let s = SecretKey::rand();
    let S = &s * G;

    let poly = Polynomial::rand(s.clone(), threshold);

    let shares = poly.shares(parties);
    let S_shares = &shares * G;

    let r_s = shares.recover();
    assert!(s == r_s);

    let r_S = S_shares.recover();
    assert!(S == r_S);
  }
}
