use crate::integer::block_decomposition::BitBlockDecomposer;
use crate::shortint::parameters::MessageModulus;

pub(crate) trait KnowsMessageModulus {
    fn message_modulus(&self) -> MessageModulus;
}

impl KnowsMessageModulus for crate::shortint::ClientKey {
    fn message_modulus(&self) -> MessageModulus {
        self.parameters.message_modulus()
    }
}

impl<OpOrder: crate::shortint::PBSOrderMarker> KnowsMessageModulus
    for crate::shortint::PublicKeyBase<OpOrder>
{
    fn message_modulus(&self) -> MessageModulus {
        self.parameters.message_modulus()
    }
}

impl<OpOrder: crate::shortint::PBSOrderMarker> KnowsMessageModulus
    for crate::shortint::CompressedPublicKeyBase<OpOrder>
{
    fn message_modulus(&self) -> MessageModulus {
        self.parameters.message_modulus()
    }
}

impl KnowsMessageModulus for crate::shortint::ServerKey {
    fn message_modulus(&self) -> MessageModulus {
        self.message_modulus
    }
}

/// Encrypts an arbitrary sized number under radix decomposition
///
/// - Each block in encrypted under the same `encrypting_key`.
/// - `num_block` is the number of radix block the final ciphertext will have.
pub(crate) fn encrypt_radix_impl<BlockKey, Block, RadixCiphertextType, T, F>(
    encrypting_key: &BlockKey,
    message: T,
    num_blocks: usize,
    encrypt_block: F,
) -> RadixCiphertextType
where
    T: bytemuck::Pod,
    BlockKey: KnowsMessageModulus,
    F: Fn(&BlockKey, u64) -> Block,
    RadixCiphertextType: From<Vec<Block>>,
{
    let message_modulus = encrypting_key.message_modulus().0 as u64;
    assert!(message_modulus.is_power_of_two());
    let bits_in_message = message_modulus.ilog2();
    let mut decomposer = BitBlockDecomposer::new_little_endian(&message, bits_in_message as u8);

    let mut blocks = Vec::with_capacity(num_blocks);
    for _ in 0..num_blocks {
        let clear_block_value = decomposer.next().unwrap_or(0);
        let encrypted_block = encrypt_block(encrypting_key, clear_block_value);
        blocks.push(encrypted_block);
    }

    RadixCiphertextType::from(blocks)
}

pub(crate) fn encrypt_crt<BlockKey, Block, CrtCiphertextType, F>(
    encrypting_key: &BlockKey,
    message: u64,
    base_vec: Vec<u64>,
    encrypt_block: F,
) -> CrtCiphertextType
where
    F: Fn(&BlockKey, u64, MessageModulus) -> Block,
    CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
{
    let mut ctxt_vect = Vec::with_capacity(base_vec.len());

    // Put each decomposition into a new ciphertext
    for modulus in base_vec.iter().copied() {
        // encryption
        let ct = encrypt_block(encrypting_key, message, MessageModulus(modulus as usize));

        ctxt_vect.push(ct);
    }

    CrtCiphertextType::from((ctxt_vect, base_vec))
}
