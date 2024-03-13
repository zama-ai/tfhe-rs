use super::{BaseRadixCiphertext, BaseSignedRadixCiphertext};
use crate::shortint::ciphertext::CompressedModulusSwitchedCiphertext;

/// An object to store a ciphertext in little memory.
/// Decompressing it requires a PBS
///
/// # Example
///
/// ```rust
/// use tfhe::integer::gen_keys_radix;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
/// use tfhe::shortint::PBSParameters;
///
/// // We have 4 * 2 = 8 bits of message
/// let size = 4;
/// let (cks, sks) = gen_keys_radix::<PBSParameters>(PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(), size);
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
pub type CompressedModulusSwitchedRadixCiphertext =
    BaseRadixCiphertext<CompressedModulusSwitchedCiphertext>;

/// An object to store a signed ciphertext in little memory.
/// Decompressing it requires a PBS
///
/// # Example
///
/// ```rust
/// use tfhe::integer::gen_keys_radix;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
/// use tfhe::shortint::PBSParameters;
///
/// // We have 4 * 2 = 8 bits of message
/// let size = 4;
/// let (cks, sks) = gen_keys_radix::<PBSParameters>(PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(), size);
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
pub type CompressedModulusSwitchedSignedRadixCiphertext =
    BaseSignedRadixCiphertext<CompressedModulusSwitchedCiphertext>;
