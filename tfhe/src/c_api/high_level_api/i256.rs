/// w0, w1, w2, w3 are words in little endian order
/// using two's complement representation
#[repr(C)]
#[derive(Copy, Clone)]
pub struct I256 {
    pub w0: u64,
    pub w1: u64,
    pub w2: u64,
    pub w3: u64,
}

impl From<crate::integer::I256> for I256 {
    fn from(value: crate::integer::I256) -> Self {
        Self {
            w0: value.0[0],
            w1: value.0[1],
            w2: value.0[2],
            w3: value.0[3],
        }
    }
}

impl From<I256> for crate::integer::I256 {
    fn from(value: I256) -> Self {
        Self([value.w0, value.w1, value.w2, value.w3])
    }
}
