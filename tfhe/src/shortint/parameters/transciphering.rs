use crate::named::Named;
use crate::shortint::backward_compatibility::parameters::transciphering::TranscipheringParametersVersions;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use super::{AtomicPatternParameters, OprfParameters};

/// Parameters of the key material used by the transciphering subsystem.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(TranscipheringParametersVersions)]
#[non_exhaustive]
pub enum TranscipheringParameters {
    /// Generate the transciphering key with the parameters of the compute key.
    SameAsCompute,
    /// Use dedicated parameters for the oprf, but stream ciphers are still evaluated with the
    /// compute key
    DedicatedOprf(OprfParameters),
}

impl TranscipheringParameters {
    /// The parameters of the OPRF key these describe, resolved against the compute parameters
    /// they are used alongside.
    pub const fn oprf_parameters(self, compute_params: AtomicPatternParameters) -> OprfParameters {
        match self {
            Self::SameAsCompute => OprfParameters::same_as_compute(compute_params),
            Self::DedicatedOprf(oprf_params) => oprf_params,
        }
    }
}

impl Named for TranscipheringParameters {
    const NAME: &'static str = "shortint::TranscipheringParameters";
}
