#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct u256 {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
}

#[inline(always)]
pub const fn to_double_digit(lo: u64, hi: u64) -> u128 {
    (lo as u128) | ((hi as u128) << u64::BITS)
}

#[inline(always)]
pub const fn adc(l: u64, r: u64, c: bool) -> (u64, bool) {
    let (lr, o0) = l.overflowing_add(r);
    let (lrc, o1) = lr.overflowing_add(c as u64);
    (lrc, o0 | o1)
}

#[inline(always)]
pub const fn mul_with_carry(l: u64, r: u64, c: u64) -> (u64, u64) {
    let res = (l as u128 * r as u128) + c as u128;
    (res as u64, (res >> 64) as u64)
}

impl u256 {
    pub const MAX: Self = Self {
        x0: u64::MAX,
        x1: u64::MAX,
        x2: u64::MAX,
        x3: u64::MAX,
    };

    #[inline(always)]
    pub const fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let lhs = self;

        let mut carry = false;
        let x0;
        let x1;
        let x2;
        let x3;

        (x0, carry) = adc(lhs.x0, rhs.x0, carry);
        (x1, carry) = adc(lhs.x1, rhs.x1, carry);
        (x2, carry) = adc(lhs.x2, rhs.x2, carry);
        (x3, carry) = adc(lhs.x3, rhs.x3, carry);

        (Self { x0, x1, x2, x3 }, carry)
    }

    #[inline(always)]
    pub const fn wrapping_add(self, rhs: Self) -> Self {
        self.overflowing_add(rhs).0
    }

    pub const fn div_rem_u256_u64(self, rhs: u64) -> (Self, u64) {
        let lhs = self;

        let mut rem = 0;
        let rhs = rhs as u128;

        let double = to_double_digit(lhs.x3, rem);
        let q = double / rhs;
        let r = double % rhs;
        rem = r as u64;
        let x3 = q as u64;

        let double = to_double_digit(lhs.x2, rem);
        let q = double / rhs;
        let r = double % rhs;
        rem = r as u64;
        let x2 = q as u64;

        let double = to_double_digit(lhs.x1, rem);
        let q = double / rhs;
        let r = double % rhs;
        rem = r as u64;
        let x1 = q as u64;

        let double = to_double_digit(lhs.x0, rem);
        let q = double / rhs;
        let r = double % rhs;
        rem = r as u64;
        let x0 = q as u64;

        (Self { x0, x1, x2, x3 }, rem)
    }

    #[inline(always)]
    pub const fn mul_u256_u64(self, rhs: u64) -> (Self, u64) {
        let mut carry = 0;
        let (x0, x1, x2, x3);

        (x0, carry) = mul_with_carry(self.x0, rhs, carry);
        (x1, carry) = mul_with_carry(self.x1, rhs, carry);
        (x2, carry) = mul_with_carry(self.x2, rhs, carry);
        (x3, carry) = mul_with_carry(self.x3, rhs, carry);

        (Self { x0, x1, x2, x3 }, carry)
    }

    #[inline(always)]
    pub const fn mul_u256_u128(self, rhs: u128) -> (Self, u128) {
        let (x, x4) = Self::mul_u256_u64(self, rhs as u64);
        let (y, y5) = Self::mul_u256_u64(self, (rhs >> 64) as u64);
        let y4 = y.x3;
        let y = u256 {
            x0: 0,
            x1: y.x0,
            x2: y.x1,
            x3: y.x2,
        };

        let (r, carry) = x.overflowing_add(y);
        let (r4, carry) = adc(x4, y4, carry);
        let r5 = y5 + carry as u64;

        (r, to_double_digit(r4, r5))
    }

    #[inline(always)]
    pub const fn wrapping_mul_u256_u128(self, rhs: u128) -> Self {
        let (x, _) = Self::mul_u256_u64(self, rhs as u64);
        let (y, _) = Self::mul_u256_u64(self, (rhs >> 64) as u64);
        let y = u256 {
            x0: 0,
            x1: y.x0,
            x2: y.x1,
            x3: y.x2,
        };
        x.wrapping_add(y)
    }
}
