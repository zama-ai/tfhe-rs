/// Meant to be implemented on the inner server key
/// eg the crate::integer::ServerKey
pub trait EvaluationIntegerKey<ClientKey> {
    fn new(client_key: &ClientKey) -> Self;

    fn new_wopbs_key(
        client_key: &ClientKey,
        server_key: &Self,
        wopbs_block_parameters: crate::shortint::WopbsParameters,
    ) -> crate::integer::wopbs::WopbsKey;
}

/// Trait to mark Id type for integers
pub trait IntegerId: Copy + Default {
    type InnerCiphertext: crate::integer::ciphertext::IntegerRadixCiphertext;
    type InnerCompressedCiphertext;

    fn num_blocks() -> usize;
}
