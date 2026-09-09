use std::fmt;
use std::str::FromStr;

use crate::error::SpecParseError;

/// The shape of an asymmetric fixed-point multiply-add: the widths of its two
/// operands, and the extra low bits dropped from the product beyond the right
/// operand's width. Two shapes with the same operand widths can still differ in
/// rescaling, so all three are needed to tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulAddShapeConfig {
    pub lhs_bits: u32,
    pub rhs_bits: u32,
    pub rescaling_bits: u32,
}

impl fmt::Display for MulAddShapeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let &Self {
            lhs_bits,
            rhs_bits,
            rescaling_bits,
        } = self;

        write!(
            f,
            "{lhs_bits}_bits_x_{rhs_bits}_bits_rescaling_{rescaling_bits}"
        )
    }
}

impl FromStr for MulAddShapeConfig {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unknown = || SpecParseError::Unknown(format!("unknown mul-add shape: {s:?}"));

        let (lhs, rest) = s.split_once("_bits_x_").ok_or_else(unknown)?;
        let (rhs, rescaling) = rest.split_once("_bits_rescaling_").ok_or_else(unknown)?;

        Ok(Self {
            lhs_bits: lhs.parse().map_err(|_| unknown())?,
            rhs_bits: rhs.parse().map_err(|_| unknown())?,
            rescaling_bits: rescaling.parse().map_err(|_| unknown())?,
        })
    }
}
