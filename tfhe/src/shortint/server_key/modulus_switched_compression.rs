use crate::shortint::atomic_pattern::AtomicPatternOperations;
use crate::shortint::ciphertext::CompressedModulusSwitchedCiphertext;
use crate::shortint::server_key::{GenericServerKey, LookupTableOwned};
use crate::shortint::Ciphertext;

impl<AP: AtomicPatternOperations> GenericServerKey<AP> {
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
    /// use tfhe::shortint::server_key::ClassicalServerKeyView;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let sks = ClassicalServerKeyView::try_from(sks.as_view()).unwrap();
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
