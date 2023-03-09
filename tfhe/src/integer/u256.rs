#[inline(always)]
pub const fn adc(l: u64, r: u64, c: bool) -> (u64, bool) {
    let (lr, o0) = l.overflowing_add(r);
    let (lrc, o1) = lr.overflowing_add(c as u64);
    (lrc, o0 | o1)
}

// Little endian order
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct U256(pub(crate) [u64; 4]);

#[cfg(test)]
impl rand::distributions::Distribution<U256> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> U256 {
        U256([rng.gen(), rng.gen(), rng.gen(), rng.gen()])
    }
}

// Since we store as [low, high], deriving ord
// would produces bad ordering
impl std::cmp::Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let mut current_ord = std::cmp::Ordering::Equal;
        for (w_self, w_other) in self.0.iter().rev().zip(other.0.iter().rev()) {
            current_ord = w_self.cmp(w_other);
            if current_ord != std::cmp::Ordering::Equal {
                break;
            }
        }

        current_ord
    }
}

impl std::ops::Add<Self> for U256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let (x0, carry) = adc(self.0[0], rhs.0[0], false);
        let (x1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (x2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (x3, _) = adc(self.0[3], rhs.0[3], carry);

        Self([x0, x1, x2, x3])
    }
}

impl std::ops::AddAssign<Self> for U256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::cmp::PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<(u128, u128)> for U256 {
    fn from(v: (u128, u128)) -> Self {
        Self([
            (v.0 & u128::from(u64::MAX)) as u64,
            (v.0 >> 64) as u64,
            (v.1 & u128::from(u64::MAX)) as u64,
            (v.1 >> 64) as u64,
        ])
    }
}

impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        Self([
            (value & u128::from(u64::MAX)) as u64,
            (value >> 64) as u64,
            0,
            0,
        ])
    }
}
