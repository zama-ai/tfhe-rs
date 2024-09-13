pub mod params;
pub mod runtime;

use crate::ffi;
use hw_regmap::FlatRegmap;
/// Trait used to extract/parse information from Rtl registers
pub trait FromRtl {
    fn from_rtl(ffi_hw: &mut ffi::HpuHw, regmap: &FlatRegmap) -> Self;
}
