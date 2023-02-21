#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct U256(pub(crate) [u128; 2]);

impl U256 {
    #[inline]
    pub fn low(&self) -> u128 {
        self.0[0]
    }

    #[inline]
    pub fn high(&self) -> u128 {
        self.0[1]
    }

    #[inline]
    pub fn low_mut(&mut self) -> &mut u128 {
        &mut self.0[0]
    }

    #[inline]
    pub fn high_mut(&mut self) -> &mut u128 {
        &mut self.0[1]
    }
}

#[cfg(test)]
impl rand::distributions::Distribution<U256> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> U256 {
        let low = rng.gen::<u128>();
        let high = rng.gen::<u128>();
        U256::from((low, high))
    }
}

// Since we store as [low, high], deriving ord
// would produces bad ordering
impl std::cmp::Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let high_bits_ord = self.high().cmp(&other.high());
        if let std::cmp::Ordering::Equal = high_bits_ord {
            self.low().cmp(&other.low())
        } else {
            high_bits_ord
        }
    }
}

impl std::ops::Add<Self> for U256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let (new_low, has_overflowed) = self.low().overflowing_add(rhs.low());
        let new_high = self
            .high()
            .wrapping_add(rhs.high())
            .wrapping_add(u128::from(has_overflowed));

        Self::from((new_low, new_high))
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
        Self([v.0, v.1])
    }
}

impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        Self::from((value, 0))
    }
}
