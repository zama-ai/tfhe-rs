use crate::named::Named;
use crate::shortint::backward_compatibility::parameters::transciphering::TranscipheringParametersVersions;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Parameters of the key material used by the transciphering subsystem.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(TranscipheringParametersVersions)]
#[non_exhaustive]
pub enum TranscipheringParameters {
    /// Generate the transciphering key with the parameters of the compute key.
    SameAsCompute,
}

impl Named for TranscipheringParameters {
    const NAME: &'static str = "shortint::TranscipheringParameters";
}
