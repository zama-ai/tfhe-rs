use std::fmt;
use std::str::FromStr;

use crate::error::SpecParseError;

/// The shape of a CUDA keyswitch benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl fmt::Display for CudaKeyswitchConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}b", self.bits)?;
        if let Some(uses_gemm) = self.uses_gemm {
            f.write_str(if uses_gemm { "::gemm" } else { "::classical" })?;
        }
        if let Some(trivial) = self.trivial_indices {
            f.write_str(if trivial {
                "::trivial_indices"
            } else {
                "::complex_indices"
            })?;
        }
        Ok(())
    }
}

impl FromStr for CudaKeyswitchConfig {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unknown = || SpecParseError::Unknown(format!("unknown keyswitch config: {s:?}"));

        let mut segments = s.split("::");
        let bits = segments
            .next()
            .and_then(|head| head.strip_suffix('b'))
            .and_then(|digits| digits.parse().ok())
            .ok_or_else(unknown)?;

        let mut config = Self::new(bits, None, None);
        for segment in segments {
            match segment {
                "gemm" => config.uses_gemm = Some(true),
                "classical" => config.uses_gemm = Some(false),
                "trivial_indices" => config.trivial_indices = Some(true),
                "complex_indices" => config.trivial_indices = Some(false),
                _ => return Err(unknown()),
            }
        }
        Ok(config)
    }
}
