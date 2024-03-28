use crate::conformance::ParameterSetConformant;
use crate::integer::BooleanBlock;
use crate::named::Named;
use crate::prelude::FheTryEncrypt;
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::CiphertextConformanceParams;
use crate::shortint::{CompressedCiphertext, PBSParameters};
use crate::{ClientKey, FheBool, ServerKey};
use serde::{Deserialize, Serialize};

/// Compressed [FheBool]
///
/// Meant to save in storage space / transfer.
///
/// - A Compressed type must be decompressed before it can be used.
/// - It is not possible to compress an existing [FheBool], compression can only be achieved at
///   encryption time
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, CompressedFheBool, ConfigBuilder};
///
/// let (client_key, _) = generate_keys(ConfigBuilder::default());
/// let compressed = CompressedFheBool::encrypt(true, &client_key);
///
/// let decompressed = compressed.decompress();
/// let decrypted: bool = decompressed.decrypt(&client_key);
/// assert_eq!(decrypted, true);
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedFheBool {
    pub(in crate::high_level_api) ciphertext: CompressedCiphertext,
}

impl CompressedFheBool {
    pub(in crate::high_level_api) fn new(ciphertext: CompressedCiphertext) -> Self {
        Self { ciphertext }
    }

    /// Decompresses itself into a [FheBool]
    ///
    /// See [CompressedFheBool] example.
    pub fn decompress(&self) -> FheBool {
        let mut ciphertext = FheBool::new(BooleanBlock::new_unchecked(
            self.ciphertext.clone().decompress(),
        ));
        ciphertext.ciphertext.move_to_device_of_server_key_if_set();
        ciphertext
    }
}

impl FheTryEncrypt<bool, ClientKey> for CompressedFheBool {
    type Error = crate::high_level_api::errors::Error;

    /// Creates a compressed encryption of a boolean value
    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let mut ciphertext = key.key.key.key.encrypt_compressed(u64::from(value));
        ciphertext.degree = Degree::new(1);
        Ok(Self::new(ciphertext))
    }
}

pub struct CompressedFheBoolConformanceParams(CiphertextConformanceParams);

impl<P> From<P> for CompressedFheBoolConformanceParams
where
    P: Into<PBSParameters>,
{
    fn from(params: P) -> Self {
        let mut params = params.into().to_shortint_conformance_param();
        params.degree = Degree::new(1);
        Self(params)
    }
}

impl From<&ServerKey> for CompressedFheBoolConformanceParams {
    fn from(sk: &ServerKey) -> Self {
        let mut parameter_set = Self(sk.key.pbs_key().key.conformance_params());
        parameter_set.0.degree = Degree::new(1);
        parameter_set
    }
}

impl ParameterSetConformant for CompressedFheBool {
    type ParameterSet = CompressedFheBoolConformanceParams;

    fn is_conformant(&self, params: &CompressedFheBoolConformanceParams) -> bool {
        self.ciphertext.is_conformant(&params.0)
    }
}

impl Named for CompressedFheBool {
    const NAME: &'static str = "high_level_api::CompressedFheBool";
}
