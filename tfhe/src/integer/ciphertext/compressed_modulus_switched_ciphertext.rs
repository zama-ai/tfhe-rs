use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::integer::backward_compatibility::ciphertext::{
    CompressedModulusSwitchedRadixCiphertextGenericVersions,
    CompressedModulusSwitchedRadixCiphertextVersions,
    CompressedModulusSwitchedSignedRadixCiphertextVersions,
};
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::shortint::ciphertext::{CompressedModulusSwitchedCiphertext, MaxDegree};
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
/// let dec = cks.decrypt(&decompressed_ct);
///
/// assert_eq!(clear, dec);
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedRadixCiphertextVersions)]
pub struct CompressedModulusSwitchedRadixCiphertext(
    pub(crate) CompressedModulusSwitchedRadixCiphertextGeneric,
);

impl ParameterSetConformant for CompressedModulusSwitchedRadixCiphertext {
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
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
/// let dec = cks.decrypt_signed(&decompressed_ct);
///
/// assert_eq!(clear, dec);
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchedSignedRadixCiphertextVersions)]
pub struct CompressedModulusSwitchedSignedRadixCiphertext(
    pub(crate) CompressedModulusSwitchedRadixCiphertextGeneric,
);

impl ParameterSetConformant for CompressedModulusSwitchedSignedRadixCiphertext {
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
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

impl ParameterSetConformant for CompressedModulusSwitchedRadixCiphertextGeneric {
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
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
            true
        };

        paired_blocks_len_ok && paired_blocks_ok && last_item_ok
    }
}
