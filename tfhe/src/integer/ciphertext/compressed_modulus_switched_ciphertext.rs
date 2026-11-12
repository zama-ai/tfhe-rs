use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::integer::backward_compatibility::ciphertext::{
    CompressedModulusSwitchedRadixCiphertextGenericVersions,
    CompressedModulusSwitchedRadixCiphertextVersions,
    CompressedModulusSwitchedSignedRadixCiphertextVersions,
};
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::shortint::ciphertext::{
    CompressedModulusSwitchedCiphertext, CompressedModulusSwitchedCiphertextConformanceParams,
    MaxDegree,
};
use crate::shortint::parameters::Degree;

/// An object to store a ciphertext using less memory.
/// Decompressing it requires a PBS
///
/// # Example
///
/// ```rust
/// use tfhe::integer::gen_keys_radix;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
/// use tfhe::shortint::PBSParameters;
///
/// // We have 4 * 2 = 8 bits of message
/// let size = 4;
/// let (cks, sks) =
///     gen_keys_radix::<PBSParameters>(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128.into(), size);
///
/// let clear = 3u8;
///
/// let ctxt = cks.encrypt(clear);
///
/// let compressed_ct = sks.switch_modulus_and_compress_parallelized(&ctxt);
///
/// let decompressed_ct = sks.decompress_parallelized(&compressed_ct);
///
/// let dec: u8 = cks.decrypt(&decompressed_ct);
///
/// assert_eq!(clear, dec);
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedRadixCiphertextVersions)]
pub struct CompressedModulusSwitchedRadixCiphertext(
    pub(crate) CompressedModulusSwitchedRadixCiphertextGeneric,
);

impl ParameterSetConformant for CompressedModulusSwitchedRadixCiphertext {
    type ParameterSet = CompressedModulusSwitchedRadixCiphertextConformanceParams;

    fn is_conformant(
        &self,
        params: &CompressedModulusSwitchedRadixCiphertextConformanceParams,
    ) -> bool {
        let Self(ct) = self;

        ct.is_conformant(params)
    }
}

/// An object to store a signed ciphertext using less memory.
/// Decompressing it requires a PBS
///
/// # Example
///
/// ```rust
/// use tfhe::integer::gen_keys_radix;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
/// use tfhe::shortint::PBSParameters;
///
/// // We have 4 * 2 = 8 bits of message
/// let size = 4;
/// let (cks, sks) =
///     gen_keys_radix::<PBSParameters>(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128.into(), size);
///
/// let clear = -3i8;
///
/// let ctxt = cks.encrypt_signed(clear);
///
/// let compressed_ct = sks.switch_modulus_and_compress_signed_parallelized(&ctxt);
///
/// let decompressed_ct = sks.decompress_signed_parallelized(&compressed_ct);
///
/// let dec: i8 = cks.decrypt_signed(&decompressed_ct);
///
/// assert_eq!(clear, dec);
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedSignedRadixCiphertextVersions)]
pub struct CompressedModulusSwitchedSignedRadixCiphertext(
    pub(crate) CompressedModulusSwitchedRadixCiphertextGeneric,
);

impl ParameterSetConformant for CompressedModulusSwitchedSignedRadixCiphertext {
    type ParameterSet = CompressedModulusSwitchedRadixCiphertextConformanceParams;

    fn is_conformant(
        &self,
        params: &CompressedModulusSwitchedRadixCiphertextConformanceParams,
    ) -> bool {
        let Self(ct) = self;

        ct.is_conformant(params)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedRadixCiphertextGenericVersions)]
pub(crate) struct CompressedModulusSwitchedRadixCiphertextGeneric {
    pub paired_blocks: Vec<CompressedModulusSwitchedCiphertext>,
    pub last_block: Option<CompressedModulusSwitchedCiphertext>,
}

#[derive(Copy, Clone)]
pub struct CompressedModulusSwitchedRadixCiphertextConformanceParams {
    pub shortint_params: CompressedModulusSwitchedCiphertextConformanceParams,
    pub num_blocks_per_integer: usize,
}

impl From<CompressedModulusSwitchedRadixCiphertextConformanceParams>
    for RadixCiphertextConformanceParams
{
    fn from(value: CompressedModulusSwitchedRadixCiphertextConformanceParams) -> Self {
        Self {
            shortint_params: value.shortint_params.into(),
            num_blocks_per_integer: value.num_blocks_per_integer,
        }
    }
}

impl ParameterSetConformant for CompressedModulusSwitchedRadixCiphertextGeneric {
    type ParameterSet = CompressedModulusSwitchedRadixCiphertextConformanceParams;

    fn is_conformant(
        &self,
        params: &CompressedModulusSwitchedRadixCiphertextConformanceParams,
    ) -> bool {
        let Self {
            paired_blocks,
            last_block,
        } = self;

        let mut shortint_params = params.shortint_params;

        shortint_params.degree = Degree::new(
            MaxDegree::from_msg_carry_modulus(
                shortint_params.message_modulus,
                shortint_params.carry_modulus,
            )
            .get(),
        );

        let paired_blocks_len_ok = paired_blocks.len() == params.num_blocks_per_integer / 2;

        let paired_blocks_ok = paired_blocks
            .iter()
            .all(|block| block.is_conformant(&shortint_params));

        let last_item_ok = if params.num_blocks_per_integer % 2 == 1 {
            last_block
                .as_ref()
                .is_some_and(|last_block| last_block.is_conformant(&params.shortint_params))
        } else {
            last_block.is_none()
        };

        paired_blocks_len_ok && paired_blocks_ok && last_item_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::{IntegerKeyKind, RadixCiphertext, ServerKey};
    use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    #[test]
    fn test_even_blocks_rejects_unexpected_last_block_conformance() {
        let num_blocks = 4;
        let (cks, sks) = KEY_CACHE.get_from_params(
            TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            IntegerKeyKind::Radix,
        );

        let conformance_params = CompressedModulusSwitchedRadixCiphertextConformanceParams {
            shortint_params: sks.key.compressed_modswitched_conformance_params(),
            num_blocks_per_integer: num_blocks,
        };

        let ct = cks.encrypt_radix(3u64, num_blocks);
        let mut compressed = sks.switch_modulus_and_compress_parallelized(&ct);
        assert!(compressed.0.last_block.is_none());
        assert!(compressed.is_conformant(&conformance_params));

        // An even number of blocks is fully stored in paired_blocks, an extra block would
        // decompress to num_blocks + 1 blocks
        let extra_block = sks
            .key
            .switch_modulus_and_compress(&cks.encrypt_one_block(1u64));
        compressed.0.last_block = Some(extra_block.clone());
        assert!(!compressed.is_conformant(&conformance_params));

        let signed_ct = cks.encrypt_signed_radix(-3i64, num_blocks);
        let mut signed_compressed = sks.switch_modulus_and_compress_signed_parallelized(&signed_ct);
        assert!(signed_compressed.is_conformant(&conformance_params));

        signed_compressed.0.last_block = Some(extra_block);
        assert!(!signed_compressed.is_conformant(&conformance_params));
    }

    /// Mimics a server handling untrusted inputs: anything that passes conformance is then
    /// decompressed and computed on, so it must not be able to make the server panic
    fn conformant_decompress_and_add(
        sks: &ServerKey,
        conformance_params: &CompressedModulusSwitchedRadixCiphertextConformanceParams,
        lhs: &CompressedModulusSwitchedRadixCiphertext,
        rhs: &CompressedModulusSwitchedRadixCiphertext,
    ) -> Option<RadixCiphertext> {
        if !lhs.is_conformant(conformance_params) || !rhs.is_conformant(conformance_params) {
            return None;
        }

        let lhs = sks.decompress_parallelized(lhs);
        let rhs = sks.decompress_parallelized(rhs);

        Some(sks.add_parallelized(&lhs, &rhs))
    }

    #[test]
    fn test_even_blocks_extra_last_block_does_not_panic_after_conformance() {
        let num_blocks = 4;
        let (cks, sks) = KEY_CACHE.get_from_params(
            TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            IntegerKeyKind::Radix,
        );

        let conformance_params = CompressedModulusSwitchedRadixCiphertextConformanceParams {
            shortint_params: sks.key.compressed_modswitched_conformance_params(),
            num_blocks_per_integer: num_blocks,
        };

        let honest = cks.encrypt_radix(3u64, num_blocks);

        // num_blocks + 2 blocks give one more paired_block than expected
        let too_many_pairs = cks.encrypt_radix(3u64, num_blocks + 2);

        // num_blocks + 1 blocks give the same number of paired_blocks as num_blocks, plus a
        // last_block that would decompress to an extra block
        let extra_last_block = cks.encrypt_radix(3u64, num_blocks + 1);

        let res = conformant_decompress_and_add(
            &sks,
            &conformance_params,
            &sks.switch_modulus_and_compress_parallelized(&honest),
            &sks.switch_modulus_and_compress_parallelized(&honest),
        )
        .unwrap();
        let dec: u64 = cks.decrypt_radix(&res);
        assert_eq!(dec, 6);

        assert!(conformant_decompress_and_add(
            &sks,
            &conformance_params,
            &sks.switch_modulus_and_compress_parallelized(&honest),
            &sks.switch_modulus_and_compress_parallelized(&too_many_pairs),
        )
        .is_none());

        assert!(conformant_decompress_and_add(
            &sks,
            &conformance_params,
            &sks.switch_modulus_and_compress_parallelized(&honest),
            &sks.switch_modulus_and_compress_parallelized(&extra_last_block),
        )
        .is_none());
    }
}
