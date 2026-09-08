use crate::shortint::parameters::{OprfParameters, TranscipheringParameters};
use crate::shortint::prelude::LweDimension;

pub const V1_8_TRANSCIPHERING_PARAM_DEDICATED_OPRF: TranscipheringParameters =
    TranscipheringParameters::DedicatedOprf(OprfParameters {
        lwe_dimension: LweDimension(600),
    });
