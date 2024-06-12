use crate::backward_compatibility::booleans::CompressedFheBoolVersions;
use crate::conformance::ParameterSetConformant;
use crate::high_level_api::global_state::with_cpu_internal_keys;
use crate::integer::BooleanBlock;
use crate::named::Named;
use crate::prelude::FheTryEncrypt;
use crate::shortint::ciphertext::{CompressedModulusSwitchedCiphertext, Degree};
use crate::shortint::CompressedCiphertext;
use crate::{ClientKey, FheBool, FheBoolConformanceParams};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

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
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompressedFheBoolVersions)]
pub enum CompressedFheBool {
    Seeded(CompressedCiphertext),
    ModulusSwitched(CompressedModulusSwitchedCiphertext),
}

impl CompressedFheBool {
    pub(in crate::high_level_api) fn new(ciphertext: CompressedCiphertext) -> Self {
        Self::Seeded(ciphertext)
    }

    /// Decompresses itself into a [FheBool]
    ///
    /// See [CompressedFheBool] example.
    pub fn decompress(&self) -> FheBool {
        let mut ciphertext = FheBool::new(BooleanBlock::new_unchecked(match self {
            Self::Seeded(seeded) => seeded.decompress(),
            Self::ModulusSwitched(modulus_switched) => {
                with_cpu_internal_keys(|sk| sk.key.key.decompress(modulus_switched))
            }
        }));

        ciphertext.ciphertext.move_to_device_of_server_key_if_set();

        ciphertext
    }
}

impl FheTryEncrypt<bool, ClientKey> for CompressedFheBool {
    type Error = crate::Error;

    /// Creates a compressed encryption of a boolean value
    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let mut ciphertext = key.key.key.key.encrypt_compressed(u64::from(value));
        ciphertext.degree = Degree::new(1);
        Ok(Self::new(ciphertext))
    }
}

impl ParameterSetConformant for CompressedFheBool {
    type ParameterSet = FheBoolConformanceParams;

    fn is_conformant(&self, params: &FheBoolConformanceParams) -> bool {
        match self {
            Self::Seeded(seeded) => seeded.is_conformant(&params.0),
            Self::ModulusSwitched(ct) => ct.is_conformant(&params.0),
        }
    }
}

impl Named for CompressedFheBool {
    const NAME: &'static str = "high_level_api::CompressedFheBool";
}

impl FheBool {
    pub fn compress(&self) -> CompressedFheBool {
        CompressedFheBool::ModulusSwitched(with_cpu_internal_keys(|sk| {
            sk.key
                .key
                .switch_modulus_and_compress(&self.ciphertext.on_cpu().0)
        }))
    }
}
