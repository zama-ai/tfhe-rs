//! Module with primitives pertaining to [`CudaLweCompactCiphertextList`] expansion.

use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_compact_ciphertext_list::CudaLweCompactCiphertextList;
use crate::core_crypto::gpu::UnsignedInteger;

/// Expand an [`CudaLweCompactCiphertextList`] into an [`CudaLweCiphertextList`].
/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronized
pub unsafe fn expand_lwe_compact_ciphertext_list_async<T>(
    output_lwe_ciphertext_list: &mut CudaLweCiphertextList<T>,
    input_lwe_compact_ciphertext_list: &CudaLweCompactCiphertextList<T>,
) where
    T: UnsignedInteger,
{
}
