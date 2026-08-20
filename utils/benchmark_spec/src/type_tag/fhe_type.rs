use std::fmt;
use std::str::FromStr;

use crate::error::SpecParseError;

/// A ciphertext or clear-text integer type, as the benches name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FheType {
    /// `FheUint64`
    Uint(u32),
    /// `FheInt32`
    Int(u32),
    /// A clear-text integer: `u64`, `i32`.
    Clear { signed: bool, bits: u32 },
}

impl fmt::Display for FheType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Uint(bits) => write!(f, "FheUint{bits}"),
            Self::Int(bits) => write!(f, "FheInt{bits}"),
            Self::Clear { signed, bits } => {
                write!(f, "{}{bits}", if signed { 'i' } else { 'u' })
            }
        }
    }
}

impl FromStr for FheType {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bits = |digits: &str| digits.parse::<u32>().ok();

        if let Some(n) = s.strip_prefix("FheUint").and_then(bits) {
            return Ok(Self::Uint(n));
        }
        if let Some(n) = s.strip_prefix("FheInt").and_then(bits) {
            return Ok(Self::Int(n));
        }
        for (prefix, signed) in [("u", false), ("i", true)] {
            if let Some(n) = s.strip_prefix(prefix).and_then(bits) {
                return Ok(Self::Clear { signed, bits: n });
            }
        }
        Err(SpecParseError::Unknown(format!("unknown type: {s:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ciphertext type and a clear one are told apart by their prefix.
    #[test]
    fn ciphertext_types_are_not_read_as_clear_ones() {
        assert_eq!("FheUint64".parse::<FheType>().unwrap(), FheType::Uint(64));
        assert_eq!(
            "u64".parse::<FheType>().unwrap(),
            FheType::Clear {
                signed: false,
                bits: 64
            }
        );
    }
}
