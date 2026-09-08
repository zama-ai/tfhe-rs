use crate::conformance::ParameterSetConformant;
use crate::named::Named;
use crate::shortint::oprf::{
    CompressedOprfServerKey, ExpandedOprfServerKey, OprfKeyConformanceParams, OprfPrivateKey,
    OprfServerKey,
};
use crate::shortint::parameters::TranscipheringParameters;
use crate::shortint::ClientKey;
use crate::transciphering::backward_compatibility::{
    CompressedTranscipheringServerKeyVersions, TranscipheringPrivateKeyVersions,
    TranscipheringServerKeyVersions,
};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Secret key material of the transciphering subsystem.
///
/// Its OPRF key is sampled independently of the general purpose one, so that the key material
/// handed to a client (symmetric keys, one time pads) does not derive from a key used elsewhere.
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(TranscipheringPrivateKeyVersions)]
pub struct TranscipheringPrivateKey {
    oprf_key: OprfPrivateKey,
    params: TranscipheringParameters,
}

impl TranscipheringPrivateKey {
    pub fn new(ck: &ClientKey, params: TranscipheringParameters) -> Self {
        let oprf_key = match params {
            TranscipheringParameters::SameAsCompute => OprfPrivateKey::new(ck),
            TranscipheringParameters::DedicatedOprf(oprf_params) => {
                OprfPrivateKey::new_with_params(ck, oprf_params)
            }
        };

        Self { oprf_key, params }
    }

    pub fn oprf_key(&self) -> &OprfPrivateKey {
        &self.oprf_key
    }

    pub fn params(&self) -> TranscipheringParameters {
        self.params
    }

    pub fn from_raw_parts(oprf_key: OprfPrivateKey, params: TranscipheringParameters) -> Self {
        Self { oprf_key, params }
    }

    pub fn into_raw_parts(self) -> (OprfPrivateKey, TranscipheringParameters) {
        (self.oprf_key, self.params)
    }
}

/// Key material of the transciphering subsystem.
///
/// Taking this rather than a plain [`OprfServerKey`] is what keeps the ciphers from drawing their
/// key material from the general purpose OPRF key or, through it, from the compute key.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(TranscipheringServerKeyVersions)]
pub struct TranscipheringServerKey {
    oprf_key: OprfServerKey,
}

/// The key bootstraps into the compute key, so it is checked against the compute parameters, plus
/// the OPRF parameters it was generated with.
///
/// A key that does not match them makes the pseudo random generation it is used for panic.
impl ParameterSetConformant for TranscipheringServerKey {
    type ParameterSet = OprfKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.oprf_key.is_conformant(parameter_set)
    }
}

impl TranscipheringServerKey {
    pub fn new(sk: &TranscipheringPrivateKey, target_ck: &ClientKey) -> crate::Result<Self> {
        OprfServerKey::new(sk.oprf_key(), target_ck).map(|oprf_key| Self { oprf_key })
    }

    pub fn oprf_key(&self) -> &OprfServerKey {
        &self.oprf_key
    }

    pub fn from_raw_parts(oprf_key: OprfServerKey) -> Self {
        Self { oprf_key }
    }

    pub fn into_raw_parts(self) -> OprfServerKey {
        self.oprf_key
    }
}

/// Seeded form of [`TranscipheringServerKey`], which is what gets stored and transmitted.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompressedTranscipheringServerKeyVersions)]
pub struct CompressedTranscipheringServerKey {
    oprf_key: CompressedOprfServerKey,
}

impl ParameterSetConformant for CompressedTranscipheringServerKey {
    type ParameterSet = OprfKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        self.oprf_key.is_conformant(parameter_set)
    }
}

impl CompressedTranscipheringServerKey {
    pub fn new(sk: &TranscipheringPrivateKey, target_ck: &ClientKey) -> crate::Result<Self> {
        CompressedOprfServerKey::new(sk.oprf_key(), target_ck).map(|oprf_key| Self { oprf_key })
    }

    pub fn expand(&self) -> ExpandedTranscipheringServerKey {
        ExpandedTranscipheringServerKey {
            oprf_key: self.oprf_key.expand(),
        }
    }

    pub fn oprf_key(&self) -> &CompressedOprfServerKey {
        &self.oprf_key
    }

    pub fn from_raw_parts(oprf_key: CompressedOprfServerKey) -> Self {
        Self { oprf_key }
    }

    pub fn into_raw_parts(self) -> CompressedOprfServerKey {
        self.oprf_key
    }
}

/// [`CompressedTranscipheringServerKey`] expanded to the standard domain, before the Fourier
/// conversion done by [`Self::to_fourier`].
#[derive(PartialEq, Eq)]
pub struct ExpandedTranscipheringServerKey {
    oprf_key: ExpandedOprfServerKey,
}

impl ExpandedTranscipheringServerKey {
    pub fn to_fourier(&self) -> TranscipheringServerKey {
        TranscipheringServerKey {
            oprf_key: self.oprf_key.to_fourier(),
        }
    }

    pub fn from_raw_parts(oprf_key: ExpandedOprfServerKey) -> Self {
        Self { oprf_key }
    }

    pub fn into_raw_parts(self) -> ExpandedOprfServerKey {
        self.oprf_key
    }
}

impl Named for TranscipheringPrivateKey {
    const NAME: &'static str = "transciphering::TranscipheringPrivateKey";
}

impl Named for TranscipheringServerKey {
    const NAME: &'static str = "transciphering::TranscipheringServerKey";
}

impl Named for CompressedTranscipheringServerKey {
    const NAME: &'static str = "transciphering::CompressedTranscipheringServerKey";
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::shortint::atomic_pattern::AtomicPatternParameters;
    use crate::shortint::parameters::test_params::{
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::parameters::OprfParameters;
    use crate::shortint::prelude::*;

    /// Builds the transciphering keys for `transciphering_params` and checks them against every
    /// entry of `expectations`.
    fn check_conformance(
        cks: &ClientKey,
        transciphering_params: TranscipheringParameters,
        expectations: &[(OprfKeyConformanceParams, bool)],
    ) {
        let private_key = TranscipheringPrivateKey::new(cks, transciphering_params);

        let server_key = TranscipheringServerKey::new(&private_key, cks).unwrap();
        let compressed = CompressedTranscipheringServerKey::new(&private_key, cks).unwrap();
        // Decompressing must preserve conformance.
        let expanded = compressed.expand().to_fourier();

        for (conformance_params, expected) in expectations {
            assert_eq!(server_key.is_conformant(conformance_params), *expected);
            assert_eq!(compressed.is_conformant(conformance_params), *expected);
            assert_eq!(expanded.is_conformant(conformance_params), *expected);
        }
    }

    #[test]
    fn transciphering_server_key_conformance() {
        let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let other_params = TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128;

        let (cks, _sks) = gen_keys(params);

        let compute: AtomicPatternParameters = params.into();
        let other_compute: AtomicPatternParameters = other_params.into();

        check_conformance(
            &cks,
            TranscipheringParameters::SameAsCompute,
            &[
                (OprfKeyConformanceParams::same_as_compute(compute), true),
                (
                    OprfKeyConformanceParams::same_as_compute(other_compute),
                    false,
                ),
            ],
        );
    }

    #[test]
    fn transciphering_server_key_conformance_dedicated_oprf() {
        let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let (cks, _sks) = gen_keys(params);

        let compute: AtomicPatternParameters = params.into();
        let dedicated = OprfParameters {
            lwe_dimension: LweDimension(600),
        };

        check_conformance(
            &cks,
            TranscipheringParameters::DedicatedOprf(dedicated),
            &[
                // A dedicated key must not pass for a key mirroring the compute parameters.
                (OprfKeyConformanceParams::same_as_compute(compute), false),
                (OprfKeyConformanceParams::new(compute, dedicated), true),
            ],
        );

        check_conformance(
            &cks,
            TranscipheringParameters::SameAsCompute,
            &[
                (OprfKeyConformanceParams::same_as_compute(compute), true),
                (OprfKeyConformanceParams::new(compute, dedicated), false),
            ],
        );
    }
}
