#![macro_use]
#![allow(unused_macros)]

//-----------------------------------------------------------------------------------------------------------
// Neg Variants
//-----------------------------------------------------------------------------------------------------------
macro_rules! neg_variant {
  (Type = $typ:ty) => {
    impl Neg for $typ {
      type Output = $typ;
      fn neg(self) -> $typ {
        -&self
      }
    }
  };
}

//-----------------------------------------------------------------------------------------------------------
// Add Variants
//-----------------------------------------------------------------------------------------------------------
macro_rules! add_assign_variant {
  (Type = $typ:ty) => {
    impl AddAssign<$typ> for $typ {
      fn add_assign(&mut self, rhs: $typ) {
        *self += &rhs;
      }
    }
  }
}

macro_rules! add_variants {
  (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty $(; Commutative = $com:ty)?) => {
    impl Add<$rhs> for $lhs {
      type Output = $out;
      fn add(self, rhs: $rhs) -> $out {
        &self + &rhs
      }
    }

    impl<'a> Add<&'a $rhs> for $lhs {
      type Output = $out;
      fn add(self, rhs: &'a $rhs) -> $out {
        &self + rhs
      }
    }

    impl<'a> Add<$rhs> for &'a $lhs {
      type Output = $out;
      fn add(self, rhs: $rhs) -> $out {
        self + &rhs
      }
    }

    $(
      impl<'a, 'b> Add<&'b $lhs> for &'a $rhs {
        type Output = $com;
        fn add(self, lhs: &'b $lhs) -> $com {
          lhs - self
        }
      }
  
      impl Add<$lhs> for $rhs {
        type Output = $com;
        fn add(self, lhs: $lhs) -> $com {
          &lhs - &self
        }
      }
  
      impl<'a> Add<&'a $lhs> for $rhs {
        type Output = $com;
        fn add(self, lhs: &'a $lhs) -> $com {
          lhs - &self
        }
      }
  
      impl<'a> Add<$lhs> for &'a $rhs {
        type Output = $com;
        fn add(self, lhs: $lhs) -> $com {
          &lhs - self
        }
      }
    )?
  };
}

//-----------------------------------------------------------------------------------------------------------
// Sub Variants
//-----------------------------------------------------------------------------------------------------------
macro_rules! sub_assign_variant {
  (Type = $typ:ty) => {
    impl<'a> SubAssign<$typ> for $typ {
      fn sub_assign(&mut self, rhs: $typ) {
        *self -= &rhs;
      }
    }
  }
}

macro_rules! sub_variants {
  (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty $(; Commutative = $com:ty)?) => {
    impl Sub<$rhs> for $lhs {
      type Output = $out;
      fn sub(self, rhs: $rhs) -> $out {
        &self - &rhs
      }
    }

    impl<'a> Sub<&'a $rhs> for $lhs {
      type Output = $out;
      fn sub(self, rhs: &'a $rhs) -> $out {
        &self - rhs
      }
    }

    impl<'a> Sub<$rhs> for &'a $lhs {
      type Output = $out;
      fn sub(self, rhs: $rhs) -> $out {
        self - &rhs
      }
    }

    $(
      impl<'a, 'b> Sub<&'b $lhs> for &'a $rhs {
        type Output = $com;
        fn sub(self, lhs: &'b $lhs) -> $com {
          lhs - self
        }
      }
  
      impl Sub<$lhs> for $rhs {
        type Output = $com;
        fn sub(self, lhs: $lhs) -> $com {
          &lhs - &self
        }
      }
  
      impl<'a> Sub<&'a $lhs> for $rhs {
        type Output = $com;
        fn sub(self, lhs: &'a $lhs) -> $com {
          lhs - &self
        }
      }
  
      impl<'a> Sub<$lhs> for &'a $rhs {
        type Output = $com;
        fn sub(self, lhs: $lhs) -> $com {
          &lhs - self
        }
      }
    )?
  };
}

//-----------------------------------------------------------------------------------------------------------
// Mul Variants
//-----------------------------------------------------------------------------------------------------------
macro_rules! mul_assign_variant {
  (Type = $typ:ty) => {
    impl<'a> MulAssign<$typ> for $typ {
      fn mul_assign(&mut self, rhs: $typ) {
        *self *= &rhs;
      }
    }
  }
}
macro_rules! mul_variants {
  (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty $(; Commutative = $com:ty)?) => {
    impl Mul<$rhs> for $lhs {
      type Output = $out;
      fn mul(self, rhs: $rhs) -> $out {
        &self * &rhs
      }
    }

    impl<'b> Mul<&'b $rhs> for $lhs {
      type Output = $out;
      fn mul(self, rhs: &'b $rhs) -> $out {
        &self * rhs
      }
    }

    impl<'a> Mul<$rhs> for &'a $lhs {
      type Output = $out;
      fn mul(self, rhs: $rhs) -> $out {
        self * &rhs
      }
    }

    $(
      impl<'a, 'b> Mul<&'b $lhs> for &'a $rhs {
        type Output = $com;
        fn mul(self, lhs: &'b $lhs) -> $com {
          lhs * self
        }
      }
  
      impl Mul<$lhs> for $rhs {
        type Output = $com;
        fn mul(self, lhs: $lhs) -> $com {
          &lhs * &self
        }
      }
  
      impl<'a> Mul<&'a $lhs> for $rhs {
        type Output = $com;
        fn mul(self, lhs: &'a $lhs) -> $com {
          lhs * &self
        }
      }
  
      impl<'a> Mul<$lhs> for &'a $rhs {
        type Output = $com;
        fn mul(self, lhs: $lhs) -> $com {
          &lhs * self
        }
      }
    )?
  };
}
