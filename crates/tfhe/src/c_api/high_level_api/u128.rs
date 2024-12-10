#[repr(C)]
#[derive(Copy, Clone)]
pub struct U128 {
    pub w0: u64,
    pub w1: u64,
}

impl From<u128> for U128 {
    fn from(value: u128) -> Self {
        let w0 = (value & (u64::MAX as u128)) as u64;
        let w1 = (value >> 64) as u64;
        Self { w0, w1 }
    }
}

impl From<U128> for u128 {
    fn from(value: U128) -> Self {
        ((value.w1 as Self) << 64u128) | value.w0 as Self
    }
}
