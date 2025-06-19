use super::{
    extract_lwe_sample_from_glwe_ciphertext, multi_bit_deterministic_blind_rotate_assign,
    GlweCiphertext, ShortintBootstrappingKey,
};
use crate::core_crypto::commons::parameters::MonomialDegree;
use crate::core_crypto::prelude::{
    CastFrom, CastInto, CompressedModulusSwitchedMultiBitLweCiphertext, ComputationBuffers,
    LweCiphertextMutView, LweCiphertextView, ToCompressedModulusSwitchedLweCiphertext,
    UnsignedInteger, UnsignedTorus,
};
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::{
    CompressedModulusSwitchedCiphertext, InternalCompressedModulusSwitchedCiphertext,
};
use crate::shortint::server_key::{
    apply_standard_blind_rotate, GenericServerKey, LookupTableOwned,
};
use crate::shortint::Ciphertext;

pub(crate) fn switch_modulus_and_compress<Scalar>(
    ciphertext: LweCiphertextView<Scalar>,
    bootstrapping_key: &ShortintBootstrappingKey<Scalar>,
) -> InternalCompressedModulusSwitchedCiphertext
where
    Scalar: UnsignedInteger + CastFrom<usize> + CastInto<u64>,
{
    match bootstrapping_key {
        ShortintBootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        } => {
            let log_modulus = bsk.polynomial_size().to_blind_rotation_input_modulus_log();

            let msed = modulus_switch_noise_reduction_key
                .lwe_ciphertext_modulus_switch::<u64, _>(&ciphertext, log_modulus);

            let compressed = msed.compress::<u64>();

            InternalCompressedModulusSwitchedCiphertext::Classic(compressed)
        }
        ShortintBootstrappingKey::MultiBit { fourier_bsk, .. } => {
            let compressed = CompressedModulusSwitchedMultiBitLweCiphertext::compress(
                &ciphertext,
                bootstrapping_key
                    .polynomial_size()
                    .to_blind_rotation_input_modulus_log(),
                fourier_bsk.grouping_factor(),
            );

            InternalCompressedModulusSwitchedCiphertext::MultiBit(compressed)
        }
    }
}

pub(crate) fn decompress_and_apply_lookup_table<InputScalar, OutputScalar>(
    compressed_ct: &CompressedModulusSwitchedCiphertext,
    acc: &GlweCiphertext<Vec<OutputScalar>>,
    bootstrapping_key: &ShortintBootstrappingKey<InputScalar>,
    ciphertext_buffer: &mut LweCiphertextMutView<OutputScalar>,
    buffers: &mut ComputationBuffers,
) where
    InputScalar: UnsignedInteger + CastInto<usize> + CastFrom<usize> + CastFrom<u64> + Sync,
    OutputScalar: UnsignedTorus + CastFrom<usize>,
{
    let mut local_accumulator = GlweCiphertext::new(
        OutputScalar::ZERO,
        acc.glwe_size(),
        acc.polynomial_size(),
        acc.ciphertext_modulus(),
    );
    local_accumulator.as_mut().copy_from_slice(acc.as_ref());

    match &bootstrapping_key {
        ShortintBootstrappingKey::Classic { bsk, .. } => {
            let ct = match &compressed_ct.compressed_modulus_switched_lwe_ciphertext {
                InternalCompressedModulusSwitchedCiphertext::Classic(a) => a.extract(),
                InternalCompressedModulusSwitchedCiphertext::MultiBit(_) => {
                    panic!(
                        "Compression was done targeting a MultiBit bootstrap decompression, \
cannot decompress with a Classic bootstrapping key"
                    )
                }
            };

            apply_standard_blind_rotate(bsk, &ct, &mut local_accumulator, buffers);
        }
        ShortintBootstrappingKey::MultiBit {
            fourier_bsk,
            thread_count,
            deterministic_execution: _,
        } => {
            let ct = match &compressed_ct.compressed_modulus_switched_lwe_ciphertext {
                InternalCompressedModulusSwitchedCiphertext::MultiBit(a) => a.extract(),
                InternalCompressedModulusSwitchedCiphertext::Classic(_) => {
                    panic!(
                        "Compression was done targeting a Classic bootstrap decompression, \
cannot decompress with a MultiBit bootstrapping key"
                    )
                }
            };

            multi_bit_deterministic_blind_rotate_assign(
                &ct,
                &mut local_accumulator,
                fourier_bsk,
                *thread_count,
            );
        }
    }

    extract_lwe_sample_from_glwe_ciphertext(
        &local_accumulator,
        ciphertext_buffer,
        MonomialDegree(0),
    );
}

impl<AP: AtomicPattern> GenericServerKey<AP> {
    /// Compresses a ciphertext to have a smaller serialization size
    ///
    /// See [`CompressedModulusSwitchedCiphertext#example`] for usage
    pub fn switch_modulus_and_compress(
        &self,
        ct: &Ciphertext,
    ) -> CompressedModulusSwitchedCiphertext {
        self.atomic_pattern.switch_modulus_and_compress(ct)
    }

    /// Decompresses a compressed ciphertext
    /// The degree from before the compression is conserved.
    /// This operation uses a PBS. For the same cost, it's possible to apply a lookup table by
    /// calling `decompress_and_apply_lookup_table` instead.
    ///
    /// See [`CompressedModulusSwitchedCiphertext#example`] for usage
    pub fn decompress(&self, compressed_ct: &CompressedModulusSwitchedCiphertext) -> Ciphertext {
        let acc = self.generate_lookup_table(|a| a);

        let mut result = self.decompress_and_apply_lookup_table(compressed_ct, &acc);

        result.degree = compressed_ct.degree;

        result
    }

    /// Decompresses a compressed ciphertext
    /// This operation uses a PBS so we can apply a lookup table
    /// An identity lookup table may be applied to get the pre compression ciphertext with a nominal
    /// noise, however, it's better to call `decompress` for that because it conserves the degree
    /// instead of setting it to the  max of the lookup table
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 3;
    ///
    /// let ctxt = cks.unchecked_encrypt(clear);
    ///
    /// // Can be serialized in a smaller buffer
    /// let compressed_ct = sks.switch_modulus_and_compress(&ctxt);
    ///
    /// let lut = sks.generate_lookup_table(|a| a + 1);
    ///
    /// let decompressed_ct = sks.decompress_and_apply_lookup_table(&compressed_ct, &lut);
    ///
    /// let dec = cks.decrypt_message_and_carry(&decompressed_ct);
    ///
    /// assert_eq!(clear + 1, dec);
    /// ```
    pub fn decompress_and_apply_lookup_table(
        &self,
        compressed_ct: &CompressedModulusSwitchedCiphertext,
        acc: &LookupTableOwned,
    ) -> Ciphertext {
        self.atomic_pattern
            .decompress_and_apply_lookup_table(compressed_ct, acc)
    }
}
