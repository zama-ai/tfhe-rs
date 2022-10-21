use crate::core_crypto::commons::crypto::encoding::FloatEncoder as ImplFloatEncoder;
use crate::core_crypto::prelude::markers::EncoderKind;
use crate::core_crypto::prelude::{AbstractEntity, EncoderEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// An encoder for 64 bits floating point numbers.
#[derive(Debug, PartialEq)]
pub struct FloatEncoder(pub(crate) ImplFloatEncoder);

impl AbstractEntity for FloatEncoder {
    type Kind = EncoderKind;
}
impl EncoderEntity for FloatEncoder {}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum FloatEncoderVersion {
    V0,
    #[serde(other)]
    Unsupported,
}

/// Parameters allowing to construct a `FloatEncoder` from the bounds of the range to be
/// represented.
#[derive(Debug, PartialEq, Clone)]
pub struct FloatEncoderMinMaxConfig {
    pub min: f64,
    pub max: f64,
    pub nb_bit_precision: usize,
    pub nb_bit_padding: usize,
}

impl FloatEncoderMinMaxConfig {
    pub(crate) fn to_commons(&self) -> ImplFloatEncoder {
        assert!(
            self.min < self.max,
            "Min and max bounds are in the wrong order."
        );
        assert_ne!(
            self.nb_bit_precision, 0,
            "The number of bits of precision must be strictly positive."
        );
        let margin: f64 =
            (self.max - self.min) / (f64::powi(2., self.nb_bit_precision as i32) - 1.);
        ImplFloatEncoder {
            o: self.min,
            delta: self.max - self.min + margin,
            nb_bit_precision: self.nb_bit_precision,
            nb_bit_padding: self.nb_bit_padding,
            round: false,
        }
    }
}

/// Parameters allowing to construct a `FloatEncoder` from the center and radius of the range to be
/// represented.
#[derive(Debug, PartialEq, Clone)]
pub struct FloatEncoderCenterRadiusConfig {
    pub center: f64,
    pub radius: f64,
    pub nb_bit_precision: usize,
    pub nb_bit_padding: usize,
}

impl FloatEncoderCenterRadiusConfig {
    pub(crate) fn to_commons(&self) -> ImplFloatEncoder {
        assert!(self.radius > 0., "Radius must be greater than zero.");
        assert_ne!(
            self.nb_bit_precision, 0,
            "The number of bits of precision must be strictly positive"
        );
        FloatEncoderMinMaxConfig {
            min: self.center - self.radius,
            max: self.center + self.radius,
            nb_bit_precision: self.nb_bit_precision,
            nb_bit_padding: self.nb_bit_padding,
        }
        .to_commons()
    }
}
