use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_lwe_keyswitch_key, par_allocate_and_generate_new_lwe_bootstrap_key,
    par_allocate_and_generate_new_lwe_multi_bit_bootstrap_key, LweBootstrapKeyOwned,
    LweMultiBitBootstrapKeyOwned,
};
use crate::integer::ClientKey;
use crate::shortint::ciphertext::MaxDegree;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::{CarryModulus, CiphertextModulus, MessageModulus, PBSOrder};

mod radix;

pub enum CudaBootstrappingKey {
    Classic(CudaLweBootstrapKey),
    MultiBit(CudaLweMultiBitBootstrapKey),
}

/// A structure containing the server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic circuits.
// #[derive(PartialEq, Serialize, Deserialize)]
pub struct CudaServerKey {
    pub key_switching_key: CudaLweKeyswitchKey<u64>,
    pub bootstrapping_key: CudaBootstrappingKey,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
    // Modulus use for computations on the ciphertext
    pub ciphertext_modulus: CiphertextModulus,
    pub pbs_order: PBSOrder,
}

impl CudaServerKey {
    /// Generates a server key that stores keys in the device memory.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::CudaServerKey;
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Generate the server key:
    /// let sks = CudaServerKey::new(&cks, &mut stream);
    /// ```
    pub fn new<C>(cks: C, stream: &CudaStream) -> Self
    where
        C: AsRef<ClientKey>,
    {
        // It should remain just enough space to add a carry
        let client_key = cks.as_ref();
        let max_degree = MaxDegree::integer_radix_server_key(
            client_key.key.parameters.message_modulus(),
            client_key.key.parameters.carry_modulus(),
        );
        Self::new_server_key_with_max_degree(client_key, max_degree, stream)
    }

    pub(crate) fn new_server_key_with_max_degree(
        cks: &ClientKey,
        max_degree: MaxDegree,
        stream: &CudaStream,
    ) -> Self {
        let mut engine = ShortintEngine::new();

        // Generate a regular keyset and convert to the GPU
        let pbs_params_base = &cks.parameters();
        let d_bootstrapping_key = match pbs_params_base {
            crate::shortint::PBSParameters::PBS(pbs_params) => {
                let h_bootstrap_key: LweBootstrapKeyOwned<u64> =
                    par_allocate_and_generate_new_lwe_bootstrap_key(
                        &cks.key.small_lwe_secret_key(),
                        &cks.key.glwe_secret_key,
                        pbs_params.pbs_base_log,
                        pbs_params.pbs_level,
                        pbs_params.glwe_noise_distribution,
                        pbs_params.ciphertext_modulus,
                        &mut engine.encryption_generator,
                    );

                let d_bootstrap_key =
                    CudaLweBootstrapKey::from_lwe_bootstrap_key(&h_bootstrap_key, stream);

                CudaBootstrappingKey::Classic(d_bootstrap_key)
            }
            crate::shortint::PBSParameters::MultiBitPBS(pbs_params) => {
                let h_bootstrap_key: LweMultiBitBootstrapKeyOwned<u64> =
                    par_allocate_and_generate_new_lwe_multi_bit_bootstrap_key(
                        &cks.key.small_lwe_secret_key(),
                        &cks.key.glwe_secret_key,
                        pbs_params.pbs_base_log,
                        pbs_params.pbs_level,
                        pbs_params.grouping_factor,
                        pbs_params.glwe_noise_distribution,
                        pbs_params.ciphertext_modulus,
                        &mut engine.encryption_generator,
                    );

                let d_bootstrap_key = CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(
                    &h_bootstrap_key,
                    stream,
                );

                CudaBootstrappingKey::MultiBit(d_bootstrap_key)
            }
        };

        // Creation of the key switching key
        let h_key_switching_key = allocate_and_generate_new_lwe_keyswitch_key(
            &cks.key.large_lwe_secret_key(),
            &cks.key.small_lwe_secret_key(),
            cks.parameters().ks_base_log(),
            cks.parameters().ks_level(),
            cks.parameters().lwe_noise_distribution(),
            cks.parameters().ciphertext_modulus(),
            &mut engine.encryption_generator,
        );

        let d_key_switching_key =
            CudaLweKeyswitchKey::from_lwe_keyswitch_key(&h_key_switching_key, stream);

        assert!(matches!(
            cks.parameters().encryption_key_choice().into(),
            PBSOrder::KeyswitchBootstrap
        ));

        // Pack the keys in the server key set:
        Self {
            key_switching_key: d_key_switching_key,
            bootstrapping_key: d_bootstrapping_key,
            message_modulus: cks.parameters().message_modulus(),
            carry_modulus: cks.parameters().carry_modulus(),
            max_degree,
            ciphertext_modulus: cks.parameters().ciphertext_modulus(),
            pbs_order: cks.parameters().encryption_key_choice().into(),
        }
    }

    // pub(crate) fn from_server_key(key: ServerKey, cks: &ClientKey, stream: &CudaStream) ->
    // Self {
    //
    //     let bootstrapping_key = key.bootstrapping_key;
    //
    //     let bootstrapping_key = match bootstrapping_key {
    //         ShortintBootstrappingKey::Classic(fourier_key) => {
    //             // Handle the Classic variant
    //
    // CudaBootstrappingKey::Classic(CudaLweBootstrapKey::from_lwe_bootstrap_key(fourier_key,
    // stream));         }
    //         ShortintBootstrappingKey::MultiBit { fourier_bsk, thread_count,
    // deterministic_execution } => {             // Handle the MultiBit variant
    //             CudaBootstrappingKey::MultiBit
    //                 (CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key
    //                     (fourier_bsk, stream));
    //         }
    //     };
    // }
}
