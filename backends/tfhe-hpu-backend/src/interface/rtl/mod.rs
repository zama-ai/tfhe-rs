pub mod params;
pub mod runtime;

use crate::ffi;
use hw_regmap::FlatRegmap;
use std::pin::Pin;
/// Trait used to extract/parse information from Rtl registers
pub trait FromRtl {
    fn from_rtl(ffi_pin: &mut Pin<&mut ffi::HpuHw>, regmap: &FlatRegmap) -> Self;
}
