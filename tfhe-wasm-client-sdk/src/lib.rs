#![allow(clippy::boxed_local)]
use tfhe::core_crypto::specification::engines::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Cleartext64(pub(crate) tfhe::core_crypto::prelude::Cleartext64);
#[wasm_bindgen]
pub struct CleartextVector64(
    pub(crate) tfhe::core_crypto::prelude::CleartextVector64,
);
#[wasm_bindgen]
pub struct GlweSecretKey64(pub(crate) tfhe::core_crypto::prelude::GlweSecretKey64);
#[wasm_bindgen]
pub struct LweBootstrapKey64(
    pub(crate) tfhe::core_crypto::prelude::LweBootstrapKey64,
);
#[wasm_bindgen]
pub struct LweCiphertext64(pub(crate) tfhe::core_crypto::prelude::LweCiphertext64);
#[wasm_bindgen]
pub struct LweCiphertextVector64(
    pub(crate) tfhe::core_crypto::prelude::LweCiphertextVector64,
);
#[wasm_bindgen]
pub struct LweKeyswitchKey64(
    pub(crate) tfhe::core_crypto::prelude::LweKeyswitchKey64,
);
#[wasm_bindgen]
pub struct LwePackingKeyswitchKey64(
    pub(crate) tfhe::core_crypto::prelude::LwePackingKeyswitchKey64,
);
#[wasm_bindgen]
pub struct LwePublicKey64(pub(crate) tfhe::core_crypto::prelude::LwePublicKey64);
#[wasm_bindgen]
pub struct LweSecretKey64(pub(crate) tfhe::core_crypto::prelude::LweSecretKey64);
#[wasm_bindgen]
pub struct LweSeededBootstrapKey64(
    pub(crate) tfhe::core_crypto::prelude::LweSeededBootstrapKey64,
);
#[wasm_bindgen]
pub struct LweSeededCiphertext64(
    pub(crate) tfhe::core_crypto::prelude::LweSeededCiphertext64,
);
#[wasm_bindgen]
pub struct LweSeededCiphertextVector64(
    pub(crate) tfhe::core_crypto::prelude::LweSeededCiphertextVector64,
);
#[wasm_bindgen]
pub struct LweSeededKeyswitchKey64(
    pub(crate) tfhe::core_crypto::prelude::LweSeededKeyswitchKey64,
);
#[wasm_bindgen]
pub struct Plaintext64(pub(crate) tfhe::core_crypto::prelude::Plaintext64);
#[wasm_bindgen]
pub struct PlaintextVector64(
    pub(crate) tfhe::core_crypto::prelude::PlaintextVector64,
);

#[wasm_bindgen]
pub struct DefaultEngine(pub(crate) tfhe::core_crypto::prelude::DefaultEngine);
#[wasm_bindgen]
impl DefaultEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(seeder: crate::JsFunctionSeeder) -> Result<DefaultEngine, JsError> {
        std::panic::set_hook(Box::new(console_error_panic_hook::hook));
        tfhe::core_crypto::prelude::DefaultEngine::new(Box::new(seeder))
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(DefaultEngine)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn retrieve_plaintext_vector_plaintext_vector64_u64(
        &mut self,
        plaintext: &PlaintextVector64,
    ) -> Result<Vec<u64>, JsError> {
        self.0
            .retrieve_plaintext_vector(&plaintext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn create_plaintext_vector_from_u64_plaintext_vector64(
        &mut self,
        input: &[u64],
    ) -> Result<PlaintextVector64, JsError> {
        self.0
            .create_plaintext_vector_from(input)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(PlaintextVector64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn retrieve_plaintext_plaintext64_u64(
        &mut self,
        plaintext: &Plaintext64,
    ) -> Result<u64, JsError> {
        self.0
            .retrieve_plaintext(&plaintext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn create_plaintext_from_u64_plaintext64(
        &mut self,
        input: u64,
    ) -> Result<Plaintext64, JsError> {
        self.0
            .create_plaintext_from(&input)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(Plaintext64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn transform_lwe_secret_key_to_glwe_secret_key_lwe_secret_key64_glwe_secret_key64(
        &mut self,
        lwe_secret_key: LweSecretKey64,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweSecretKey64, JsError> {
        self.0
            .transform_lwe_secret_key_to_glwe_secret_key(lwe_secret_key.0, polynomial_size.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(GlweSecretKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn transform_lwe_seeded_ciphertext_to_lwe_ciphertext_lwe_seeded_ciphertext64_lwe_ciphertext64(
        &mut self,
        lwe_seeded_ciphertext: LweSeededCiphertext64,
    ) -> Result<LweCiphertext64, JsError> {
        self.0
            .transform_lwe_seeded_ciphertext_to_lwe_ciphertext(lwe_seeded_ciphertext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertext64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_lwe_seeded_keyswitch_key64_lwe_keyswitch_key64(
        &mut self,
        lwe_seeded_keyswitch_key: LweSeededKeyswitchKey64,
    ) -> Result<LweKeyswitchKey64, JsError> {
        self.0
            .transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key(lwe_seeded_keyswitch_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweKeyswitchKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn generate_new_lwe_seeded_keyswitch_key_lwe_secret_key64_lwe_secret_key64_lwe_seeded_keyswitch_key64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &LweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LweSeededKeyswitchKey64, JsError> {
        self.0
            .generate_new_lwe_seeded_keyswitch_key(
                &input_key.0,
                &output_key.0,
                decomposition_level_count.0,
                decomposition_base_log.0,
                noise.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSeededKeyswitchKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_lwe_seeded_ciphertext_vector64_lwe_ciphertext_vector64(
        &mut self,
        lwe_seeded_ciphertext_vector: LweSeededCiphertextVector64,
    ) -> Result<LweCiphertextVector64, JsError> {
        self.0
            .transform_lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector(
                lwe_seeded_ciphertext_vector.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertextVector64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn encrypt_lwe_seeded_ciphertext_vector_lwe_secret_key64_plaintext_vector64_lwe_seeded_ciphertext_vector64(
        &mut self,
        key: &LweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<LweSeededCiphertextVector64, JsError> {
        self.0
            .encrypt_lwe_seeded_ciphertext_vector(&key.0, &input.0, noise.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSeededCiphertextVector64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn encrypt_lwe_seeded_ciphertext_lwe_secret_key64_plaintext64_lwe_seeded_ciphertext64(
        &mut self,
        key: &LweSecretKey64,
        input: &Plaintext64,
        noise: Variance,
    ) -> Result<LweSeededCiphertext64, JsError> {
        self.0
            .encrypt_lwe_seeded_ciphertext(&key.0, &input.0, noise.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSeededCiphertext64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_lwe_seeded_bootstrap_key64_lwe_bootstrap_key64(
        &mut self,
        lwe_seeded_bootstrap_key: LweSeededBootstrapKey64,
    ) -> Result<LweBootstrapKey64, JsError> {
        self.0
            .transform_lwe_seeded_bootstrap_key_to_lwe_bootstrap_key(lwe_seeded_bootstrap_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweBootstrapKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn generate_new_lwe_seeded_bootstrap_key_lwe_secret_key64_glwe_secret_key64_lwe_seeded_bootstrap_key64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweSeededBootstrapKey64, JsError> {
        self.0
            .generate_new_lwe_seeded_bootstrap_key(
                &input_key.0,
                &output_key.0,
                decomposition_base_log.0,
                decomposition_level_count.0,
                noise.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSeededBootstrapKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn generate_new_lwe_secret_key_lwe_secret_key64(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<LweSecretKey64, JsError> {
        self.0
            .generate_new_lwe_secret_key(lwe_dimension.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSecretKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn generate_new_lwe_public_key_lwe_secret_key64_lwe_public_key64(
        &mut self,
        lwe_secret_key: &LweSecretKey64,
        noise: Variance,
        lwe_public_key_zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> Result<LwePublicKey64, JsError> {
        self.0
            .generate_new_lwe_public_key(
                &lwe_secret_key.0,
                noise.0,
                lwe_public_key_zero_encryption_count.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LwePublicKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn generate_new_lwe_packing_keyswitch_key_lwe_secret_key64_glwe_secret_key64_lwe_packing_keyswitch_key64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LwePackingKeyswitchKey64, JsError> {
        self.0
            .generate_new_lwe_packing_keyswitch_key(
                &input_key.0,
                &output_key.0,
                decomposition_level_count.0,
                decomposition_base_log.0,
                noise.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LwePackingKeyswitchKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn generate_new_lwe_keyswitch_key_lwe_secret_key64_lwe_secret_key64_lwe_keyswitch_key64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &LweSecretKey64,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<LweKeyswitchKey64, JsError> {
        self.0
            .generate_new_lwe_keyswitch_key(
                &input_key.0,
                &output_key.0,
                decomposition_level_count.0,
                decomposition_base_log.0,
                noise.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweKeyswitchKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn zero_encrypt_lwe_ciphertext_lwe_secret_key64_lwe_ciphertext64(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
    ) -> Result<LweCiphertext64, JsError> {
        self.0
            .zero_encrypt_lwe_ciphertext(&key.0, noise.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertext64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn zero_encrypt_lwe_ciphertext_vector_lwe_secret_key64_lwe_ciphertext_vector64(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<LweCiphertextVector64, JsError> {
        self.0
            .zero_encrypt_lwe_ciphertext_vector(&key.0, noise.0, count.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertextVector64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn trivially_encrypt_lwe_ciphertext_vector_plaintext_vector64_lwe_ciphertext_vector64(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextVector64,
    ) -> Result<LweCiphertextVector64, JsError> {
        self.0
            .trivially_encrypt_lwe_ciphertext_vector(lwe_size.0, &input.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertextVector64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn trivially_decrypt_lwe_ciphertext_vector_lwe_ciphertext_vector64_plaintext_vector64(
        &mut self,
        input: &LweCiphertextVector64,
    ) -> Result<PlaintextVector64, JsError> {
        self.0
            .trivially_decrypt_lwe_ciphertext_vector(&input.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(PlaintextVector64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn encrypt_lwe_ciphertext_vector_lwe_secret_key64_plaintext_vector64_lwe_ciphertext_vector64(
        &mut self,
        key: &LweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<LweCiphertextVector64, JsError> {
        self.0
            .encrypt_lwe_ciphertext_vector(&key.0, &input.0, noise.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertextVector64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn discard_encrypt_lwe_ciphertext_vector_lwe_secret_key64_plaintext_vector64_lwe_ciphertext_vector64(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), JsError> {
        self.0
            .discard_encrypt_lwe_ciphertext_vector(&key.0, &mut output.0, &input.0, noise.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn discard_decrypt_lwe_ciphertext_vector_lwe_secret_key64_lwe_ciphertext_vector64_plaintext_vector64(
        &mut self,
        key: &LweSecretKey64,
        output: &mut PlaintextVector64,
        input: &LweCiphertextVector64,
    ) -> Result<(), JsError> {
        self.0
            .discard_decrypt_lwe_ciphertext_vector(&key.0, &mut output.0, &input.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn decrypt_lwe_ciphertext_vector_lwe_secret_key64_lwe_ciphertext_vector64_plaintext_vector64(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertextVector64,
    ) -> Result<PlaintextVector64, JsError> {
        self.0
            .decrypt_lwe_ciphertext_vector(&key.0, &input.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(PlaintextVector64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn trivially_encrypt_lwe_ciphertext_plaintext64_lwe_ciphertext64(
        &mut self,
        lwe_size: LweSize,
        input: &Plaintext64,
    ) -> Result<LweCiphertext64, JsError> {
        self.0
            .trivially_encrypt_lwe_ciphertext(lwe_size.0, &input.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertext64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn trivially_decrypt_lwe_ciphertext_lwe_ciphertext64_plaintext64(
        &mut self,
        input: &LweCiphertext64,
    ) -> Result<Plaintext64, JsError> {
        self.0
            .trivially_decrypt_lwe_ciphertext(&input.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(Plaintext64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn encrypt_lwe_ciphertext_lwe_secret_key64_plaintext64_lwe_ciphertext64(
        &mut self,
        key: &LweSecretKey64,
        input: &Plaintext64,
        noise: Variance,
    ) -> Result<LweCiphertext64, JsError> {
        self.0
            .encrypt_lwe_ciphertext(&key.0, &input.0, noise.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertext64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn discard_encrypt_lwe_ciphertext_with_public_key_lwe_public_key64_plaintext64_lwe_ciphertext64(
        &mut self,
        key: &LwePublicKey64,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
    ) -> Result<(), JsError> {
        self.0
            .discard_encrypt_lwe_ciphertext_with_public_key(&key.0, &mut output.0, &input.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn discard_keyswitch_lwe_ciphertext_lwe_keyswitch_key64_lwe_ciphertext64_lwe_ciphertext64(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        ksk: &LweKeyswitchKey64,
    ) -> Result<(), JsError> {
        self.0
            .discard_keyswitch_lwe_ciphertext(&mut output.0, &input.0, &ksk.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn discard_encrypt_lwe_ciphertext_lwe_secret_key64_plaintext64_lwe_ciphertext64(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
        noise: Variance,
    ) -> Result<(), JsError> {
        self.0
            .discard_encrypt_lwe_ciphertext(&key.0, &mut output.0, &input.0, noise.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn discard_decrypt_lwe_ciphertext_lwe_secret_key64_lwe_ciphertext64_plaintext64(
        &mut self,
        key: &LweSecretKey64,
        output: &mut Plaintext64,
        input: &LweCiphertext64,
    ) -> Result<(), JsError> {
        self.0
            .discard_decrypt_lwe_ciphertext(&key.0, &mut output.0, &input.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn decrypt_lwe_ciphertext_lwe_secret_key64_lwe_ciphertext64_plaintext64(
        &mut self,
        key: &LweSecretKey64,
        input: &LweCiphertext64,
    ) -> Result<Plaintext64, JsError> {
        self.0
            .decrypt_lwe_ciphertext(&key.0, &input.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(Plaintext64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn generate_new_lwe_bootstrap_key_lwe_secret_key64_glwe_secret_key64_lwe_bootstrap_key64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweBootstrapKey64, JsError> {
        self.0
            .generate_new_lwe_bootstrap_key(
                &input_key.0,
                &output_key.0,
                decomposition_base_log.0,
                decomposition_level_count.0,
                noise.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweBootstrapKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn consume_retrieve_lwe_bootstrap_key_lwe_bootstrap_key64_u64_vec(
        &mut self,
        bootstrap_key: LweBootstrapKey64,
    ) -> Result<Vec<u64>, JsError> {
        self.0
            .consume_retrieve_lwe_bootstrap_key(bootstrap_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn transform_glwe_secret_key_to_lwe_secret_key_glwe_secret_key64_lwe_secret_key64(
        &mut self,
        glwe_secret_key: GlweSecretKey64,
    ) -> Result<LweSecretKey64, JsError> {
        self.0
            .transform_glwe_secret_key_to_lwe_secret_key(glwe_secret_key.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSecretKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn generate_new_glwe_secret_key_glwe_secret_key64(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweSecretKey64, JsError> {
        self.0
            .generate_new_glwe_secret_key(glwe_dimension.0, polynomial_size.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(GlweSecretKey64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn retrieve_cleartext_vector_cleartext_vector64_u64(
        &mut self,
        cleartext: &CleartextVector64,
    ) -> Result<Vec<u64>, JsError> {
        self.0
            .retrieve_cleartext_vector(&cleartext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn create_cleartext_vector_from_u64_cleartext_vector64(
        &mut self,
        input: &[u64],
    ) -> Result<CleartextVector64, JsError> {
        self.0
            .create_cleartext_vector_from(input)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(CleartextVector64)
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn retrieve_cleartext_cleartext64_u64(
        &mut self,
        cleartext: &Cleartext64,
    ) -> Result<u64, JsError> {
        self.0
            .retrieve_cleartext(&cleartext.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultEngine {
    pub fn create_cleartext_from_u64_cleartext64(
        &mut self,
        input: u64,
    ) -> Result<Cleartext64, JsError> {
        self.0
            .create_cleartext_from(&input)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(Cleartext64)
    }
}
#[wasm_bindgen]
pub struct DefaultParallelEngine(
    pub(crate) tfhe::core_crypto::prelude::DefaultParallelEngine,
);
#[wasm_bindgen]
impl DefaultParallelEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(seeder: crate::JsFunctionSeeder) -> Result<DefaultParallelEngine, JsError> {
        std::panic::set_hook(Box::new(console_error_panic_hook::hook));
        tfhe::core_crypto::prelude::DefaultParallelEngine::new(Box::new(seeder))
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(DefaultParallelEngine)
    }
}
#[wasm_bindgen]
impl DefaultParallelEngine {
    pub fn generate_new_lwe_seeded_bootstrap_key_lwe_secret_key64_glwe_secret_key64_lwe_seeded_bootstrap_key64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweSeededBootstrapKey64, JsError> {
        self.0
            .generate_new_lwe_seeded_bootstrap_key(
                &input_key.0,
                &output_key.0,
                decomposition_base_log.0,
                decomposition_level_count.0,
                noise.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSeededBootstrapKey64)
    }
}
#[wasm_bindgen]
impl DefaultParallelEngine {
    pub fn generate_new_lwe_public_key_lwe_secret_key64_lwe_public_key64(
        &mut self,
        lwe_secret_key: &LweSecretKey64,
        noise: Variance,
        lwe_public_key_zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> Result<LwePublicKey64, JsError> {
        self.0
            .generate_new_lwe_public_key(
                &lwe_secret_key.0,
                noise.0,
                lwe_public_key_zero_encryption_count.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LwePublicKey64)
    }
}
#[wasm_bindgen]
impl DefaultParallelEngine {
    pub fn zero_encrypt_lwe_ciphertext_vector_lwe_secret_key64_lwe_ciphertext_vector64(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<LweCiphertextVector64, JsError> {
        self.0
            .zero_encrypt_lwe_ciphertext_vector(&key.0, noise.0, count.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertextVector64)
    }
}
#[wasm_bindgen]
impl DefaultParallelEngine {
    pub fn generate_new_lwe_bootstrap_key_lwe_secret_key64_glwe_secret_key64_lwe_bootstrap_key64(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweBootstrapKey64, JsError> {
        self.0
            .generate_new_lwe_bootstrap_key(
                &input_key.0,
                &output_key.0,
                decomposition_base_log.0,
                decomposition_level_count.0,
                noise.0,
            )
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweBootstrapKey64)
    }
}
#[wasm_bindgen]
pub struct DefaultSerializationEngine(
    pub(crate) tfhe::core_crypto::prelude::DefaultSerializationEngine,
);
#[wasm_bindgen]
impl DefaultSerializationEngine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<DefaultSerializationEngine, JsError> {
        std::panic::set_hook(Box::new(console_error_panic_hook::hook));
        tfhe::core_crypto::prelude::DefaultSerializationEngine::new(())
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(DefaultSerializationEngine)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_plaintext_vector64_u8_vec(
        &mut self,
        entity: &PlaintextVector64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_plaintext64_u8_vec(
        &mut self,
        entity: &Plaintext64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_public_key64_u8_vec(
        &mut self,
        entity: &LwePublicKey64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_packing_keyswitch_key64_u8_vec(
        &mut self,
        entity: &LwePackingKeyswitchKey64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_seeded_keyswitch_key64_u8_vec(
        &mut self,
        entity: &LweSeededKeyswitchKey64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_seeded_ciphertext_vector64_u8_vec(
        &mut self,
        entity: &LweSeededCiphertextVector64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_seeded_ciphertext64_u8_vec(
        &mut self,
        entity: &LweSeededCiphertext64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_seeded_bootstrap_key64_u8_vec(
        &mut self,
        entity: &LweSeededBootstrapKey64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_secret_key64_u8_vec(
        &mut self,
        entity: &LweSecretKey64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_keyswitch_key64_u8_vec(
        &mut self,
        entity: &LweKeyswitchKey64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_ciphertext_vector64_u8_vec(
        &mut self,
        entity: &LweCiphertextVector64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_ciphertext64_u8_vec(
        &mut self,
        entity: &LweCiphertext64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_lwe_bootstrap_key64_u8_vec(
        &mut self,
        entity: &LweBootstrapKey64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_glwe_secret_key64_u8_vec(
        &mut self,
        entity: &GlweSecretKey64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_cleartext_vector64_u8_vec(
        &mut self,
        entity: &CleartextVector64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn serialize_cleartext64_u8_vec(
        &mut self,
        entity: &Cleartext64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .serialize(&entity.0)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_plaintext_vector64(
        &mut self,
        serialized: &[u8],
    ) -> Result<PlaintextVector64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(PlaintextVector64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_plaintext64(
        &mut self,
        serialized: &[u8],
    ) -> Result<Plaintext64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(Plaintext64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_public_key64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LwePublicKey64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LwePublicKey64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_packing_keyswitch_key64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LwePackingKeyswitchKey64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LwePackingKeyswitchKey64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_seeded_keyswitch_key64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededKeyswitchKey64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSeededKeyswitchKey64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_seeded_ciphertext_vector64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededCiphertextVector64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSeededCiphertextVector64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_seeded_ciphertext64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededCiphertext64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSeededCiphertext64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_seeded_bootstrap_key64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededBootstrapKey64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSeededBootstrapKey64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_secret_key64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSecretKey64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweSecretKey64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_keyswitch_key64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweKeyswitchKey64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweKeyswitchKey64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_ciphertext_vector64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertextVector64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertextVector64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_ciphertext64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertext64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweCiphertext64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_lwe_bootstrap_key64(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweBootstrapKey64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(LweBootstrapKey64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_glwe_secret_key64(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweSecretKey64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(GlweSecretKey64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_cleartext_vector64(
        &mut self,
        serialized: &[u8],
    ) -> Result<CleartextVector64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(CleartextVector64)
    }
}
#[wasm_bindgen]
impl DefaultSerializationEngine {
    pub fn deserialize_u8_slice_cleartext64(
        &mut self,
        serialized: &[u8],
    ) -> Result<Cleartext64, JsError> {
        self.0
            .deserialize(serialized)
            .map_err(|e| wasm_bindgen::JsError::new(format!("{}", e).as_str()))
            .map(Cleartext64)
    }
}

mod seeder {
    use tfhe::core_crypto::commons::math::random::Seed;
    use tfhe::core_crypto::prelude::Seeder;
    use js_sys::{Function, Uint8Array};
    use std::panic;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsValue;

    const SEED_BYTES_COUNT: usize = 16;

    #[wasm_bindgen]
    pub struct JsFunctionSeeder {
        js_func: Function,
        buffer: [u8; SEED_BYTES_COUNT],
    }

    #[wasm_bindgen]
    impl JsFunctionSeeder {
        #[wasm_bindgen(constructor)]
        pub fn new(js_func: Function) -> JsFunctionSeeder {
            panic::set_hook(Box::new(console_error_panic_hook::hook));
            let buffer = [0u8; SEED_BYTES_COUNT];
            JsFunctionSeeder { js_func, buffer }
        }
    }

    impl Seeder for JsFunctionSeeder {
        fn seed(&mut self) -> Seed {
            let output = self.js_func.call0(&JsValue::NULL).unwrap();
            let array = Uint8Array::new(&output);
            if array.length() as usize != SEED_BYTES_COUNT {
                panic!("The seeder function must return a Uint8Array of size 16.");
            }
            array.copy_to(&mut self.buffer);
            let seed = u128::from_le_bytes(self.buffer);
            Seed(seed)
        }

        fn is_available() -> bool
        where
            Self: Sized,
        {
            true
        }
    }
}
pub use seeder::*;

mod commons {
    use wasm_bindgen::prelude::*;

    macro_rules! param {
        ($(($public: ident, $private: ident, $typ: ty)),*) => {
            $(
                #[wasm_bindgen]
                pub struct $public(pub(crate) tfhe::core_crypto::prelude::$private);

                #[wasm_bindgen]
                impl $public {
                    #[wasm_bindgen(constructor)]
                    pub fn new(val: $typ) -> $public {
                        $public(tfhe::core_crypto::prelude::$private(val))
                    }

                    #[wasm_bindgen]
                    pub fn unwrap(&self) -> $typ {
                        self.0.0
                    }
                }
            )*
        };
    }

    param! {
        (Variance, Variance, f64),
        (DecompositionBaseLog, DecompositionBaseLog, usize),
        (DecompositionLevelCount, DecompositionLevelCount, usize),
        (LweDimension, LweDimension, usize),
        (LweCiphertextCount, LweCiphertextCount, usize),
        (LweSize, LweSize, usize),
        (MonomialIndex, MonomialIndex, usize),
        (GlweDimension, GlweDimension, usize),
        (GlweSize, GlweSize, usize),
        (PolynomialSize, PolynomialSize, usize),
        (DeltaLog, DeltaLog, usize),
        (ExtractedBitsCount, ExtractedBitsCount, usize),
        (LwePublicKeyZeroEncryptionCount, LwePublicKeyZeroEncryptionCount, usize)
    }

    #[wasm_bindgen]
    impl LweDimension {
        #[wasm_bindgen]
        pub fn to_lwe_size(&self) -> LweSize {
            LweSize(self.0.to_lwe_size())
        }
    }

    #[wasm_bindgen]
    impl LweSize {
        #[wasm_bindgen]
        pub fn to_lwe_dimension(&self) -> LweDimension {
            LweDimension(self.0.to_lwe_dimension())
        }
    }

    #[wasm_bindgen]
    impl GlweDimension {
        #[wasm_bindgen]
        pub fn to_glwe_size(&self) -> GlweSize {
            GlweSize(self.0.to_glwe_size())
        }
    }

    #[wasm_bindgen]
    impl GlweSize {
        #[wasm_bindgen]
        pub fn to_glwe_dimension(&self) -> GlweDimension {
            GlweDimension(self.0.to_glwe_dimension())
        }
    }
}
pub use commons::*;
