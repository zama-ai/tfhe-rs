pub use crate::core_crypto::commons::math::random::Seed;
use bincode;
use wasm_bindgen::prelude::*;

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::ActivatedRandomGenerator;

use std::panic::set_hook;

#[wasm_bindgen]
pub struct BooleanCiphertext(pub(crate) crate::boolean::ciphertext::Ciphertext);

#[wasm_bindgen]
pub struct BooleanCompressedCiphertext(pub(crate) crate::boolean::ciphertext::CompressedCiphertext);

#[wasm_bindgen]
pub struct BooleanClientKey(pub(crate) crate::boolean::client_key::ClientKey);

#[wasm_bindgen]
pub struct BooleanPublicKey(pub(crate) crate::boolean::public_key::PublicKey);

#[wasm_bindgen]
pub struct BooleanCompressedServerKey(pub(crate) crate::boolean::server_key::CompressedServerKey);

#[wasm_bindgen]
pub struct Boolean {}

#[wasm_bindgen]
pub struct BooleanParameters(pub(crate) crate::boolean::parameters::BooleanParameters);

#[wasm_bindgen]
pub enum BooleanParameterSet {
    Default,
    TfheLib,
    DefaultKsPbs,
    TfheLibKsPbs,
}

impl TryFrom<u32> for BooleanParameterSet {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BooleanParameterSet::Default),
            1 => Ok(BooleanParameterSet::TfheLib),
            2 => Ok(BooleanParameterSet::DefaultKsPbs),
            3 => Ok(BooleanParameterSet::TfheLibKsPbs),
            _ => Err(format!(
                "Invalid value '{value}' for BooleansParametersSet, use \
                BooleanParameterSet constants"
            )),
        }
    }
}

#[wasm_bindgen]
pub enum BooleanEncryptionKeyChoice {
    Big,
    Small,
}

impl From<BooleanEncryptionKeyChoice>
    for crate::core_crypto::commons::parameters::EncryptionKeyChoice
{
    fn from(value: BooleanEncryptionKeyChoice) -> Self {
        match value {
            BooleanEncryptionKeyChoice::Big => {
                crate::shortint::parameters::EncryptionKeyChoice::Big
            }
            BooleanEncryptionKeyChoice::Small => {
                crate::shortint::parameters::EncryptionKeyChoice::Small
            }
        }
    }
}

#[wasm_bindgen]
impl Boolean {
    #[wasm_bindgen]
    pub fn get_parameters(parameter_choice: u32) -> Result<BooleanParameters, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        let parameter_choice = BooleanParameterSet::try_from(parameter_choice)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))?;

        match parameter_choice {
            BooleanParameterSet::Default => Ok(crate::boolean::parameters::DEFAULT_PARAMETERS),
            BooleanParameterSet::TfheLib => {
                Ok(crate::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165)
            }
            BooleanParameterSet::DefaultKsPbs => {
                Ok(crate::boolean::parameters::DEFAULT_PARAMETERS_KS_PBS)
            }
            BooleanParameterSet::TfheLibKsPbs => {
                Ok(crate::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS)
            }
        }
        .map(BooleanParameters)
    }

    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn new_parameters(
        lwe_dimension: usize,
        glwe_dimension: usize,
        polynomial_size: usize,
        lwe_modular_std_dev: f64,
        glwe_modular_std_dev: f64,
        pbs_base_log: usize,
        pbs_level: usize,
        ks_base_log: usize,
        ks_level: usize,
        encryption_key_choice: BooleanEncryptionKeyChoice,
    ) -> BooleanParameters {
        set_hook(Box::new(console_error_panic_hook::hook));
        use crate::core_crypto::prelude::*;
        BooleanParameters(crate::boolean::parameters::BooleanParameters {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_modular_std_dev: StandardDev(lwe_modular_std_dev),
            glwe_modular_std_dev: StandardDev(glwe_modular_std_dev),
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
            encryption_key_choice: encryption_key_choice.into(),
        })
    }

    #[wasm_bindgen]
    pub fn new_client_key_from_seed_and_parameters(
        seed_high_bytes: u64,
        seed_low_bytes: u64,
        parameters: &BooleanParameters,
    ) -> BooleanClientKey {
        set_hook(Box::new(console_error_panic_hook::hook));
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed: u128 = (seed_high_bytes << 64) | seed_low_bytes;

        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let key = crate::boolean::engine::BooleanEngine::new_from_seeder(&mut seeder)
            .create_client_key(parameters.0.to_owned());
        BooleanClientKey(key)
    }

    #[wasm_bindgen]
    pub fn new_client_key(parameters: &BooleanParameters) -> BooleanClientKey {
        set_hook(Box::new(console_error_panic_hook::hook));
        BooleanClientKey(crate::boolean::client_key::ClientKey::new(&parameters.0))
    }

    #[wasm_bindgen]
    pub fn new_public_key(client_key: &BooleanClientKey) -> BooleanPublicKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        BooleanPublicKey(crate::boolean::public_key::PublicKey::new(&client_key.0))
    }

    #[wasm_bindgen]
    pub fn new_compressed_server_key(client_key: &BooleanClientKey) -> BooleanCompressedServerKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        BooleanCompressedServerKey(crate::boolean::server_key::CompressedServerKey::new(
            &client_key.0,
        ))
    }

    #[wasm_bindgen]
    pub fn encrypt(client_key: &BooleanClientKey, message: bool) -> BooleanCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));
        BooleanCiphertext(client_key.0.encrypt(message))
    }

    #[wasm_bindgen]
    pub fn encrypt_compressed(
        client_key: &BooleanClientKey,
        message: bool,
    ) -> BooleanCompressedCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));
        BooleanCompressedCiphertext(client_key.0.encrypt_compressed(message))
    }

    #[wasm_bindgen]
    pub fn decompress_ciphertext(
        compressed_ciphertext: &BooleanCompressedCiphertext,
    ) -> BooleanCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));
        BooleanCiphertext(compressed_ciphertext.0.clone().into())
    }

    #[wasm_bindgen]
    pub fn encrypt_with_public_key(
        public_key: &BooleanPublicKey,
        message: bool,
    ) -> BooleanCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));

        BooleanCiphertext(public_key.0.encrypt(message))
    }

    #[wasm_bindgen]
    pub fn trivial_encrypt(&mut self, message: bool) -> BooleanCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));
        BooleanCiphertext(crate::boolean::ciphertext::Ciphertext::Trivial(message))
    }

    #[wasm_bindgen]
    pub fn decrypt(client_key: &BooleanClientKey, ct: &BooleanCiphertext) -> bool {
        set_hook(Box::new(console_error_panic_hook::hook));
        client_key.0.decrypt(&ct.0)
    }

    #[wasm_bindgen]
    pub fn serialize_ciphertext(ciphertext: &BooleanCiphertext) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_ciphertext(buffer: &[u8]) -> Result<BooleanCiphertext, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(BooleanCiphertext)
    }

    #[wasm_bindgen]
    pub fn serialize_compressed_ciphertext(
        ciphertext: &BooleanCompressedCiphertext,
    ) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_compressed_ciphertext(
        buffer: &[u8],
    ) -> Result<BooleanCompressedCiphertext, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(BooleanCompressedCiphertext)
    }

    #[wasm_bindgen]
    pub fn serialize_client_key(client_key: &BooleanClientKey) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&client_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_client_key(buffer: &[u8]) -> Result<BooleanClientKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(BooleanClientKey)
    }

    #[wasm_bindgen]
    pub fn serialize_public_key(public_key: &BooleanPublicKey) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&public_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_public_key(buffer: &[u8]) -> Result<BooleanPublicKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(BooleanPublicKey)
    }

    #[wasm_bindgen]
    pub fn serialize_compressed_server_key(
        server_key: &BooleanCompressedServerKey,
    ) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&server_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_compressed_server_key(
        buffer: &[u8],
    ) -> Result<BooleanCompressedServerKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(BooleanCompressedServerKey)
    }
}
