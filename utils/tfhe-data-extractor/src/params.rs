//! Reads a parameter set alias, which is the only place some of a result's
//! properties are recorded.
//!
//! The alias is what `NamedParam::name()` returns, so its tokens are the ones
//! the Rust constant is spelled with:
//!
//! ```text
//! V1_7_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
//! BENCH_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64
//! ```
//!
//! Carry size, atomic pattern and version are left unparsed: no table reads
//! them.

use std::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum NoiseDistribution {
    Gaussian,
    TUniform,
}

/// Spelled as the published file names carry it.
impl fmt::Display for NoiseDistribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gaussian => write!(f, "gaussian"),
            Self::TUniform => write!(f, "tuniform"),
        }
    }
}

/// Probability that an operation on a parameter set returns a wrong result.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PFail {
    TwoMinus40,
    TwoMinus64,
    TwoMinus128,
}

/// Spelled as the published file names carry it, which is the alias token
/// lowercased.
impl fmt::Display for PFail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TwoMinus40 => write!(f, "2m40"),
            Self::TwoMinus64 => write!(f, "2m64"),
            Self::TwoMinus128 => write!(f, "2m128"),
        }
    }
}

/// What the tables read out of an alias.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamSet {
    pub message_bits: u32,
    pub noise: NoiseDistribution,
    pub p_fail: PFail,
    /// Set on multi-bit sets only, from the `GROUP` token.
    pub grouping_factor: Option<u32>,
    /// Tokens before `PARAM`.
    variation: String,
}

impl ParamSet {
    /// Returns `None` for an alias that is not a shortint one, `DEFAULT_PARAMETERS`
    /// of the boolean layer being the case that turns up.
    pub fn parse(alias: &str) -> Option<Self> {
        let tokens: Vec<&str> = alias.split('_').collect();
        let tokens = strip_version(&tokens);
        let param = tokens.iter().position(|token| *token == "PARAM")?;

        Some(Self {
            message_bits: value_after(tokens, "MESSAGE")?,
            // Older aliases spell out neither, and the previous tool read them
            // as these two.
            noise: noise_distribution(tokens).unwrap_or(NoiseDistribution::TUniform),
            p_fail: p_fail(tokens).unwrap_or(PFail::TwoMinus128),
            grouping_factor: value_after(tokens, "GROUP"),
            variation: tokens[..param].join("_"),
        })
    }

    /// Whether the alias names a compute parameter set rather than a derivative
    /// of one. Compression, keyswitching and noise squashing each derive their
    /// own set, measured through their own operations, so their timings have no
    /// place in a table of compute ones.
    ///
    /// `BENCH` is not a derivative: it marks the benchmark crate's own copy of a
    /// compute set.
    pub fn is_compute_set(&self) -> bool {
        matches!(self.variation.as_str(), "" | "BENCH")
    }
}

/// Drops a leading `V<major>_<minor>` version prefix, which spans two tokens.
fn strip_version<'a, 's>(tokens: &'a [&'s str]) -> &'a [&'s str] {
    match tokens {
        [major, minor, rest @ ..]
            if major
                .strip_prefix('V')
                .is_some_and(|digits| !digits.is_empty() && is_number(digits))
                && is_number(minor) =>
        {
            rest
        }
        _ => tokens,
    }
}

fn is_number(token: &str) -> bool {
    token.chars().all(|c| c.is_ascii_digit())
}

/// Number held by the token following `name`.
fn value_after(tokens: &[&str], name: &str) -> Option<u32> {
    let index = tokens.iter().position(|token| *token == name)?;
    tokens.get(index + 1)?.parse().ok()
}

fn noise_distribution(tokens: &[&str]) -> Option<NoiseDistribution> {
    tokens.iter().find_map(|token| match *token {
        "GAUSSIAN" => Some(NoiseDistribution::Gaussian),
        "TUNIFORM" => Some(NoiseDistribution::TUniform),
        _ => None,
    })
}

fn p_fail(tokens: &[&str]) -> Option<PFail> {
    tokens
        .iter()
        .find_map(|token| match token.strip_prefix("2M")? {
            "40" => Some(PFail::TwoMinus40),
            "64" => Some(PFail::TwoMinus64),
            "128" => Some(PFail::TwoMinus128),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_classical_alias() {
        let alias = "BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128";
        let params = ParamSet::parse(alias).unwrap();

        assert_eq!(params.message_bits, 2);
        assert_eq!(params.noise, NoiseDistribution::TUniform);
        assert_eq!(params.p_fail, PFail::TwoMinus128);
        assert_eq!(params.grouping_factor, None);
        assert!(params.is_compute_set());
    }

    #[test]
    fn reads_a_multi_bit_alias() {
        let alias = "BENCH_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64";
        let params = ParamSet::parse(alias).unwrap();

        assert_eq!(params.message_bits, 1);
        assert_eq!(params.noise, NoiseDistribution::Gaussian);
        assert_eq!(params.p_fail, PFail::TwoMinus64);
        assert_eq!(params.grouping_factor, Some(3));
    }

    /// The version prefix is two tokens, and dropping only the first would make
    /// `PARAM` land one token further than it does.
    #[test]
    fn a_version_prefix_leaves_no_variation_behind() {
        let params = ParamSet::parse("V1_7_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128").unwrap();

        assert_eq!(params.message_bits, 4);
        assert_eq!(params.variation, "");
        assert!(params.is_compute_set());
    }

    #[test]
    fn a_derived_set_is_not_a_compute_one() {
        for alias in [
            "BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128",
            "V1_7_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128",
        ] {
            assert!(!ParamSet::parse(alias).unwrap().is_compute_set(), "{alias}");
        }
    }

    #[test]
    fn an_alias_without_noise_or_p_fail_falls_back() {
        let params = ParamSet::parse("PARAM_MESSAGE_2_CARRY_2").unwrap();

        assert_eq!(params.noise, NoiseDistribution::TUniform);
        assert_eq!(params.p_fail, PFail::TwoMinus128);
    }

    #[test]
    fn a_boolean_alias_is_rejected() {
        assert_eq!(ParamSet::parse("DEFAULT_PARAMETERS"), None);
        assert_eq!(ParamSet::parse("TFHE_LIB_PARAMETERS"), None);
    }
}
