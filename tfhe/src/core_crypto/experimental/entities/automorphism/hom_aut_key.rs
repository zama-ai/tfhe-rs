use crate::core_crypto::experimental::algorithms::glwe_fast_keyswitch::glwe_fast_keyswitch_wrapper;
use crate::core_crypto::experimental::algorithms::pseudo_ggsw_conversion::convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized;
use crate::core_crypto::experimental::algorithms::pseudo_ggsw_encryption::encrypt_pseudo_ggsw_ciphertext;
use crate::core_crypto::experimental::entities::automorphism::Automorphism;
use crate::core_crypto::experimental::entities::fourier_pseudo_ggsw_ciphertext::FourierPseudoGgswCiphertext;
use crate::core_crypto::experimental::entities::pseudo_ggsw_ciphertext::PseudoGgswCiphertext;
use crate::core_crypto::prelude::*;
use aligned_vec::ABox;
use serde::{Deserialize, Serialize};
use tfhe_fft::c64;

/// A combined automorphism + key-switch key for homomorphic application of a Galois automorphism.
///
/// Aut_u(Enc_sk(input)) = Enc_{Aut_u(sk)}(Aut_u(input))
///
/// To get an encryption of Aut_u(input) under sk, we need to KS from Aut_u(sk) to sk
///
/// HomAut_u(Enc_sk(input))
/// = GLWE_KS(Aut_u(sk) -> sk, Aut_u(Enc_sk(input)))
/// = GLWE_KS(Aut_u(sk) -> sk, Enc_{Aut_u(sk)}(Aut_u(input)))
/// = Enc_sk(Aut_u(input))
///
/// This struct stores an object to apply the automorphism and the GLWE KS key to go back to sk.
/// Using it, we can apply an automorphism to a polynomial encrypted in a GLWE without changing the
/// key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutomKey {
    automorphism: Automorphism,
    fourier_ksk: FourierPseudoGgswCiphertext<ABox<[c64]>>,
}

impl AutomKey {
    pub fn new<Gen: ByteRandomGenerator>(
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        automorphism: Automorphism,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        glwe_noise_distribution: DynamicDistribution<u64>,
        ciphertext_modulus: CiphertextModulus<u64>,
        encryption_generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self {
        let glwe_dimension = glwe_secret_key.glwe_dimension();
        let glwe_size = glwe_dimension.to_glwe_size();
        let polynomial_size = glwe_secret_key.polynomial_size();

        let mut autom_glwe_secret_key =
            GlweSecretKey::new_empty_key(0, glwe_dimension, polynomial_size);

        automorphism.apply_to_glwe_secret_key(glwe_secret_key, &mut autom_glwe_secret_key);

        let mut pseudo_ggsw = PseudoGgswCiphertext::new(
            0u64,
            glwe_size,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        );

        encrypt_pseudo_ggsw_ciphertext(
            glwe_secret_key,
            &autom_glwe_secret_key,
            &mut pseudo_ggsw,
            glwe_noise_distribution,
            encryption_generator,
        );

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        let mut buffers = ComputationBuffers::new();

        buffers.resize(fft.forward_scratch().unaligned_bytes_required());

        let mut fourier_ggsw = FourierPseudoGgswCiphertext::new(
            glwe_size,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        );

        convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized(
            &pseudo_ggsw,
            &mut fourier_ggsw,
            fft,
            buffers.stack(),
        );

        Self {
            automorphism,
            fourier_ksk: fourier_ggsw,
        }
    }

    /// Applies the automorphism  and the keyswitch back to the original secret key.
    /// This is an inplace operation where ct stores the input at the beginning of the function and
    /// the result in the end.
    ///
    /// `temp_ct` is used as a scratch buffer and must have the same size as `ct`.
    pub fn apply<InCont, OutCont>(
        &self,
        ct: &mut GlweCiphertext<InCont>,
        temp_ct: &mut GlweCiphertext<OutCont>,
    ) where
        InCont: ContainerMut<Element = u64>,
        OutCont: ContainerMut<Element = u64>,
    {
        self.automorphism.apply_to_glwe_ciphertext(ct, temp_ct);

        glwe_fast_keyswitch_wrapper(ct, &self.fourier_ksk, temp_ct);
    }
}
