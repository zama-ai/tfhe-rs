//! Type tags appended to a bench id: a Rust type, a precision, a
//! key/value pair or a keyswitch configuration.

use std::fmt;

pub trait TypeName {
    fn type_name(&self) -> String;
}

impl fmt::Display for dyn TypeName + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.type_name())
    }
}

#[derive(Debug)]
pub struct TypedKeyValue<'a> {
    key: &'a str,
    value: &'a str,
}

impl<'a> TypedKeyValue<'a> {
    pub fn new(key: &'a str, value: &'a str) -> Self {
        Self { key, value }
    }
}

impl TypeName for TypedKeyValue<'_> {
    fn type_name(&self) -> String {
        format!("key_{}::value_{}", self.key, self.value)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PrecisionTag {
    /// `{n}_bits`
    Bits(usize),
    /// `{n}_bits_scalar_{n}`
    BitsScalar(usize),
    /// `{from}_to_{to}`
    Conversion { from: usize, to: usize },
}

impl TypeName for PrecisionTag {
    fn type_name(&self) -> String {
        match *self {
            Self::Bits(n) => format!("{n}_bits"),
            Self::BitsScalar(n) => format!("{n}_bits_scalar_{n}"),
            Self::Conversion { from, to } => format!("{from}_to_{to}"),
        }
    }
}

#[derive(Debug)]
pub struct CudaKeyswitchConfig {
    pub bits: u32,
    pub uses_gemm: Option<bool>,
    pub trivial_indices: Option<bool>,
}

impl CudaKeyswitchConfig {
    pub fn new(bits: u32, uses_gemm: Option<bool>, trivial_indices: Option<bool>) -> Self {
        Self {
            bits,
            uses_gemm,
            trivial_indices,
        }
    }
}

impl TypeName for CudaKeyswitchConfig {
    fn type_name(&self) -> String {
        let mut name = format!("{}b", self.bits);
        if let Some(uses_gemm) = self.uses_gemm {
            name.push_str(if uses_gemm { "::gemm" } else { "::classical" });
        }
        if let Some(trivial) = self.trivial_indices {
            name.push_str(if trivial {
                "::trivial_indices"
            } else {
                "::complex_indices"
            });
        }
        name
    }
}
