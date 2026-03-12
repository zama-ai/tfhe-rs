use std::fmt;

/// Any level in the benchmark spec hierarchy must implement this.
/// Used by layers (hlapi, integer...) and bench categories (ops, erc20...).
pub(crate) trait SpecFmt: fmt::Display {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}
