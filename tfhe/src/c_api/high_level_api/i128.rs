/// w0 and w1 are words in little endian order
/// using two's complement representation
#[repr(C)]
#[derive(Copy, Clone)]
pub struct I128 {
    pub w0: u64,
    pub w1: u64,
}

impl From<i128> for I128 {
    fn from(value: i128) -> Self {
        let w0 = (value & (u64::MAX as i128)) as u64;
        let w1 = (value >> 64) as u64;
        Self { w0, w1 }
    }
}

impl From<I128> for i128 {
    fn from(value: I128) -> Self {
        ((value.w1 as Self) << 64u128) | value.w0 as Self
    }
}
