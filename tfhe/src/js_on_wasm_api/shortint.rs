use crate::core_crypto::commons::generators::DeterministicSeeder;
pub use crate::core_crypto::commons::math::random::Seed;
use crate::core_crypto::prelude::ActivatedRandomGenerator;
pub use crate::shortint::parameters::parameters_compact_pk::*;
pub use crate::shortint::parameters::*;
use bincode;
use wasm_bindgen::prelude::*;

use std::panic::set_hook;

#[wasm_bindgen]
pub struct ShortintCiphertext(pub(crate) crate::shortint::Ciphertext);

#[wasm_bindgen]
pub struct ShortintCompressedCiphertext(pub(crate) crate::shortint::CompressedCiphertext);

#[wasm_bindgen]
pub struct ShortintClientKey(pub(crate) crate::shortint::ClientKey);

#[wasm_bindgen]
pub struct ShortintPublicKey(pub(crate) crate::shortint::PublicKey);

#[wasm_bindgen]
pub struct ShortintCompressedPublicKey(pub(crate) crate::shortint::CompressedPublicKey);

#[wasm_bindgen]
pub struct ShortintCompressedServerKey(pub(crate) crate::shortint::CompressedServerKey);

#[wasm_bindgen]
pub struct Shortint {}

#[wasm_bindgen]
pub struct ShortintParameters(pub(crate) crate::shortint::ClassicPBSParameters);

#[wasm_bindgen]
pub enum ShortintEncryptionKeyChoice {
    Big,
    Small,
}

impl From<ShortintEncryptionKeyChoice> for crate::shortint::parameters::EncryptionKeyChoice {
    fn from(value: ShortintEncryptionKeyChoice) -> Self {
        match value {
            ShortintEncryptionKeyChoice::Big => {
                crate::shortint::parameters::EncryptionKeyChoice::Big
            }
            ShortintEncryptionKeyChoice::Small => {
                crate::shortint::parameters::EncryptionKeyChoice::Small
            }
        }
    }
}

macro_rules! expose_predefined_parameters {
    (
        $(
            $param_name:ident
        ),*
        $(,)?
    ) => {
        #[wasm_bindgen]
        #[allow(non_camel_case_types)]
        pub enum ShortintParametersName {
            $(
                $param_name,
            )*
        }

        #[wasm_bindgen]
        impl ShortintParameters {
            #[wasm_bindgen(constructor)]
            pub fn new(name: ShortintParametersName) -> Self {
                match name {
                    $(
                        ShortintParametersName::$param_name => {
                            Self($param_name)
                        }
                    )*
                }
            }
        }
    }
}

expose_predefined_parameters! {
    PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    PARAM_MESSAGE_3_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    PARAM_MESSAGE_4_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_KS_PBS,
    PARAM_MESSAGE_8_CARRY_0_KS_PBS,
    // Small params
    PARAM_MESSAGE_1_CARRY_1_PBS_KS,
    PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    PARAM_MESSAGE_3_CARRY_3_PBS_KS,
    PARAM_MESSAGE_4_CARRY_4_PBS_KS,
    // CPK
    PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS,
    // CPK SMALL
    PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_PBS_KS,
    // Aliases to remove eventually
    PARAM_MESSAGE_1_CARRY_0,
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_2_CARRY_0,
    PARAM_MESSAGE_1_CARRY_2,
    PARAM_MESSAGE_2_CARRY_1,
    PARAM_MESSAGE_3_CARRY_0,
    PARAM_MESSAGE_1_CARRY_3,
    PARAM_MESSAGE_2_CARRY_2,
    PARAM_MESSAGE_3_CARRY_1,
    PARAM_MESSAGE_4_CARRY_0,
    PARAM_MESSAGE_1_CARRY_4,
    PARAM_MESSAGE_2_CARRY_3,
    PARAM_MESSAGE_3_CARRY_2,
    PARAM_MESSAGE_4_CARRY_1,
    PARAM_MESSAGE_5_CARRY_0,
    PARAM_MESSAGE_1_CARRY_5,
    PARAM_MESSAGE_2_CARRY_4,
    PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_2,
    PARAM_MESSAGE_5_CARRY_1,
    PARAM_MESSAGE_6_CARRY_0,
    PARAM_MESSAGE_1_CARRY_6,
    PARAM_MESSAGE_2_CARRY_5,
    PARAM_MESSAGE_3_CARRY_4,
    PARAM_MESSAGE_4_CARRY_3,
    PARAM_MESSAGE_5_CARRY_2,
    PARAM_MESSAGE_6_CARRY_1,
    PARAM_MESSAGE_7_CARRY_0,
    PARAM_MESSAGE_1_CARRY_7,
    PARAM_MESSAGE_2_CARRY_6,
    PARAM_MESSAGE_3_CARRY_5,
    PARAM_MESSAGE_4_CARRY_4,
    PARAM_MESSAGE_5_CARRY_3,
    PARAM_MESSAGE_6_CARRY_2,
    PARAM_MESSAGE_7_CARRY_1,
    PARAM_MESSAGE_8_CARRY_0,
    // Small params
    PARAM_SMALL_MESSAGE_1_CARRY_1,
    PARAM_SMALL_MESSAGE_2_CARRY_2,
    PARAM_SMALL_MESSAGE_3_CARRY_3,
    PARAM_SMALL_MESSAGE_4_CARRY_4,
}

#[wasm_bindgen]
impl Shortint {
    #[wasm_bindgen]
    pub fn get_parameters(
        message_bits: usize,
        carry_bits: usize,
    ) -> Result<ShortintParameters, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        match (message_bits, carry_bits) {
            (1, 0) => Ok(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_0_KS_PBS),
            (1, 1) => Ok(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_1_KS_PBS),
            (2, 0) => Ok(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_0_KS_PBS),
            (1, 2) => Ok(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_2_KS_PBS),
            (2, 1) => Ok(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_1_KS_PBS),
            (3, 0) => Ok(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_0_KS_PBS),
            (1, 3) => Ok(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_3_KS_PBS),
            (2, 2) => Ok(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            (3, 1) => Ok(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_1_KS_PBS),
            (4, 0) => Ok(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_0_KS_PBS),
            (1, 4) => Ok(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_4_KS_PBS),
            (2, 3) => Ok(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_3_KS_PBS),
            (3, 2) => Ok(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_2_KS_PBS),
            (4, 1) => Ok(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_1_KS_PBS),
            (5, 0) => Ok(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_0_KS_PBS),
            (1, 5) => Ok(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_5_KS_PBS),
            (2, 4) => Ok(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_4_KS_PBS),
            (3, 3) => Ok(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS),
            (4, 2) => Ok(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_2_KS_PBS),
            (5, 1) => Ok(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_1_KS_PBS),
            (6, 0) => Ok(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_0_KS_PBS),
            (1, 6) => Ok(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_6_KS_PBS),
            (2, 5) => Ok(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_5_KS_PBS),
            (3, 4) => Ok(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_4_KS_PBS),
            (4, 3) => Ok(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_3_KS_PBS),
            (5, 2) => Ok(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_2_KS_PBS),
            (6, 1) => Ok(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_1_KS_PBS),
            (7, 0) => Ok(crate::shortint::parameters::PARAM_MESSAGE_7_CARRY_0_KS_PBS),
            (1, 7) => Ok(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_7_KS_PBS),
            (2, 6) => Ok(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_6_KS_PBS),
            (3, 5) => Ok(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_5_KS_PBS),
            (4, 4) => Ok(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_KS_PBS),
            (5, 3) => Ok(crate::shortint::parameters::PARAM_MESSAGE_5_CARRY_3_KS_PBS),
            (6, 2) => Ok(crate::shortint::parameters::PARAM_MESSAGE_6_CARRY_2_KS_PBS),
            (7, 1) => Ok(crate::shortint::parameters::PARAM_MESSAGE_7_CARRY_1_KS_PBS),
            (8, 0) => Ok(crate::shortint::parameters::PARAM_MESSAGE_8_CARRY_0_KS_PBS),
            _ => Err(wasm_bindgen::JsError::new(
                format!(
                "No parameters for {message_bits} bits of message and {carry_bits} bits of carry"
            )
                .as_str(),
            )),
        }
        .map(ShortintParameters)
    }

    #[wasm_bindgen]
    pub fn get_parameters_small(
        message_bits: usize,
        carry_bits: usize,
    ) -> Result<ShortintParameters, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        match (message_bits, carry_bits) {
            (1, 1) => Ok(crate::shortint::parameters::PARAM_MESSAGE_1_CARRY_1_PBS_KS),
            (2, 2) => Ok(crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_PBS_KS),
            (3, 3) => Ok(crate::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_PBS_KS),
            (4, 4) => Ok(crate::shortint::parameters::PARAM_MESSAGE_4_CARRY_4_PBS_KS),
            _ => Err(wasm_bindgen::JsError::new(
                format!(
                "No parameters for {message_bits} bits of message and {carry_bits} bits of carry"
            )
                .as_str(),
            )),
        }
        .map(ShortintParameters)
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
        message_modulus: usize,
        carry_modulus: usize,
        modulus_power_of_2_exponent: usize,
        encryption_key_choice: ShortintEncryptionKeyChoice,
    ) -> ShortintParameters {
        set_hook(Box::new(console_error_panic_hook::hook));
        use crate::core_crypto::prelude::*;
        ShortintParameters(crate::shortint::ClassicPBSParameters {
            lwe_dimension: LweDimension(lwe_dimension),
            glwe_dimension: GlweDimension(glwe_dimension),
            polynomial_size: PolynomialSize(polynomial_size),
            lwe_modular_std_dev: StandardDev(lwe_modular_std_dev),
            glwe_modular_std_dev: StandardDev(glwe_modular_std_dev),
            pbs_base_log: DecompositionBaseLog(pbs_base_log),
            pbs_level: DecompositionLevelCount(pbs_level),
            ks_base_log: DecompositionBaseLog(ks_base_log),
            ks_level: DecompositionLevelCount(ks_level),
            message_modulus: crate::shortint::parameters::MessageModulus(message_modulus),
            carry_modulus: crate::shortint::parameters::CarryModulus(carry_modulus),
            ciphertext_modulus: crate::shortint::parameters::CiphertextModulus::try_new_power_of_2(
                modulus_power_of_2_exponent,
            )
            .unwrap(),
            encryption_key_choice: encryption_key_choice.into(),
        })
    }

    #[wasm_bindgen]
    pub fn new_client_key_from_seed_and_parameters(
        seed_high_bytes: u64,
        seed_low_bytes: u64,
        parameters: &ShortintParameters,
    ) -> Result<ShortintClientKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed: u128 = (seed_high_bytes << 64) | seed_low_bytes;

        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder)
            .new_client_key(parameters.0.try_into().unwrap())
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintClientKey)
    }

    #[wasm_bindgen]
    pub fn new_client_key(parameters: &ShortintParameters) -> ShortintClientKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintClientKey(crate::shortint::client_key::ClientKey::new(
            parameters.0.to_owned(),
        ))
    }

    #[wasm_bindgen]
    pub fn new_public_key(client_key: &ShortintClientKey) -> ShortintPublicKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintPublicKey(crate::shortint::public_key::PublicKey::new(&client_key.0))
    }

    #[wasm_bindgen]
    pub fn new_compressed_public_key(
        client_key: &ShortintClientKey,
    ) -> ShortintCompressedPublicKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCompressedPublicKey(crate::shortint::public_key::CompressedPublicKey::new(
            &client_key.0,
        ))
    }

    #[wasm_bindgen]
    pub fn new_compressed_server_key(
        client_key: &ShortintClientKey,
    ) -> ShortintCompressedServerKey {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCompressedServerKey(crate::shortint::server_key::CompressedServerKey::new(
            &client_key.0,
        ))
    }

    #[wasm_bindgen]
    pub fn encrypt(client_key: &ShortintClientKey, message: u64) -> ShortintCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCiphertext(client_key.0.encrypt(message))
    }

    #[wasm_bindgen]
    pub fn encrypt_compressed(
        client_key: &ShortintClientKey,
        message: u64,
    ) -> ShortintCompressedCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCompressedCiphertext(client_key.0.encrypt_compressed(message))
    }

    #[wasm_bindgen]
    pub fn decompress_ciphertext(
        compressed_ciphertext: &ShortintCompressedCiphertext,
    ) -> ShortintCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));
        ShortintCiphertext(compressed_ciphertext.0.clone().into())
    }

    #[wasm_bindgen]
    pub fn encrypt_with_public_key(
        public_key: &ShortintPublicKey,
        message: u64,
    ) -> ShortintCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCiphertext(public_key.0.encrypt(message))
    }

    #[wasm_bindgen]
    pub fn encrypt_with_compressed_public_key(
        public_key: &ShortintCompressedPublicKey,
        message: u64,
    ) -> ShortintCiphertext {
        set_hook(Box::new(console_error_panic_hook::hook));

        ShortintCiphertext(public_key.0.encrypt(message))
    }

    #[wasm_bindgen]
    pub fn decrypt(client_key: &ShortintClientKey, ct: &ShortintCiphertext) -> u64 {
        set_hook(Box::new(console_error_panic_hook::hook));
        client_key.0.decrypt(&ct.0)
    }

    #[wasm_bindgen]
    pub fn serialize_ciphertext(ciphertext: &ShortintCiphertext) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_ciphertext(buffer: &[u8]) -> Result<ShortintCiphertext, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintCiphertext)
    }

    #[wasm_bindgen]
    pub fn serialize_compressed_ciphertext(
        ciphertext: &ShortintCompressedCiphertext,
    ) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_compressed_ciphertext(
        buffer: &[u8],
    ) -> Result<ShortintCompressedCiphertext, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintCompressedCiphertext)
    }

    #[wasm_bindgen]
    pub fn serialize_client_key(client_key: &ShortintClientKey) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&client_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_client_key(buffer: &[u8]) -> Result<ShortintClientKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintClientKey)
    }

    #[wasm_bindgen]
    pub fn serialize_public_key(public_key: &ShortintPublicKey) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&public_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_public_key(buffer: &[u8]) -> Result<ShortintPublicKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintPublicKey)
    }

    #[wasm_bindgen]
    pub fn serialize_compressed_public_key(
        public_key: &ShortintCompressedPublicKey,
    ) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&public_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_compressed_public_key(
        buffer: &[u8],
    ) -> Result<ShortintCompressedPublicKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintCompressedPublicKey)
    }

    #[wasm_bindgen]
    pub fn serialize_compressed_server_key(
        server_key: &ShortintCompressedServerKey,
    ) -> Result<Vec<u8>, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::serialize(&server_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
    }

    #[wasm_bindgen]
    pub fn deserialize_compressed_server_key(
        buffer: &[u8],
    ) -> Result<ShortintCompressedServerKey, JsError> {
        set_hook(Box::new(console_error_panic_hook::hook));
        bincode::deserialize(buffer)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{e:?}").as_str()))
            .map(ShortintCompressedServerKey)
    }
}
