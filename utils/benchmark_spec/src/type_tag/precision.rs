use std::fmt;
use std::str::FromStr;

use crate::error::SpecParseError;

/// How wide the operands of a benchmark are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrecisionTag {
    /// `{n}_bits`
    Bits(u32),
    /// `{n}_bits_scalar_{n}`
    BitsScalar(u32),
    /// `{from}_to_{to}`, a cast between two widths.
    Conversion { from: u32, to: u32 },
}

impl fmt::Display for PrecisionTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Bits(n) => write!(f, "{n}_bits"),
            Self::BitsScalar(n) => write!(f, "{n}_bits_scalar_{n}"),
            Self::Conversion { from, to } => write!(f, "{from}_to_{to}"),
        }
    }
}

impl FromStr for PrecisionTag {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unknown = || SpecParseError::Unknown(format!("unknown precision: {s:?}"));

        if let Some((head, scalar)) = s.split_once("_bits_scalar_") {
            let bits: u32 = head.parse().map_err(|_| unknown())?;
            // `Display` writes the same number twice; a mismatch is not this tag.
            if Some(bits) == scalar.parse().ok() {
                return Ok(Self::BitsScalar(bits));
            }
            return Err(unknown());
        }
        if let Some(n) = s.strip_suffix("_bits") {
            return Ok(Self::Bits(n.parse().map_err(|_| unknown())?));
        }
        let (from, to) = s.split_once("_to_").ok_or_else(unknown)?;
        Ok(Self::Conversion {
            from: from.parse().map_err(|_| unknown())?,
            to: to.parse().map_err(|_| unknown())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Display` writes the number twice, so a mismatch is not this tag.
    #[test]
    fn scalar_precision_is_not_read_as_plain_bits() {
        assert_eq!(
            "32_bits_scalar_32".parse::<PrecisionTag>().unwrap(),
            PrecisionTag::BitsScalar(32)
        );
        // Two different numbers were never rendered by `Display`.
        assert!("32_bits_scalar_64".parse::<PrecisionTag>().is_err());
    }
}
