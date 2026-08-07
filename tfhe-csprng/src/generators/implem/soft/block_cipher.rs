use crate::generators::aes_ctr::{
    Aes128Key, Aes256Key, AesBlockCipher, AES_CALLS_PER_BATCH, BYTES_PER_AES_CALL, BYTES_PER_BATCH,
};
use aes::cipher::consts::U16;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};

#[derive(Copy, Clone)]
pub struct Software;

impl crate::generators::implem::AesBackend for Software {
    type Aes128BlockCipher = Software128BlockCipher;

    type Aes256BlockCipher = Software256BlockCipher;
}

#[derive(Clone)]
pub struct Software128BlockCipher {
    // Aes structure
    aes: Aes128,
}

impl AesBlockCipher for Software128BlockCipher {
    type Key = Aes128Key;

    fn new(key: Self::Key) -> Software128BlockCipher {
        let key: [u8; BYTES_PER_AES_CALL] = key.0.to_ne_bytes();
        let key = Block::from(key);
        let aes = Aes128::new(&key);
        Software128BlockCipher { aes }
    }

    fn generate_batch(&mut self, data: [u128; AES_CALLS_PER_BATCH]) -> [u8; BYTES_PER_BATCH] {
        aes_encrypt_many(
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], &self.aes,
        )
    }

    fn generate_next(&mut self, data: u128) -> [u8; BYTES_PER_AES_CALL] {
        aes_encrypt_one(data, &self.aes)
    }
}

#[derive(Clone)]
pub struct Software256BlockCipher {
    // Aes structure
    aes: Aes256,
}

impl AesBlockCipher for Software256BlockCipher {
    type Key = Aes256Key;

    fn new(key: Self::Key) -> Self {
        let aes = Aes256::new(&key.0.into());
        Software256BlockCipher { aes }
    }

    fn generate_batch(&mut self, data: [u128; AES_CALLS_PER_BATCH]) -> [u8; BYTES_PER_BATCH] {
        aes_encrypt_many(
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], &self.aes,
        )
    }

    fn generate_next(&mut self, data: u128) -> [u8; BYTES_PER_AES_CALL] {
        aes_encrypt_one(data, &self.aes)
    }
}

fn aes_encrypt_one<G>(message: u128, cipher: &G) -> [u8; BYTES_PER_AES_CALL]
where
    G: BlockCipherEncrypt<BlockSize = U16>,
{
    let mut b1 = Block::from(message.to_ne_bytes());

    cipher.encrypt_block(&mut b1);

    b1.into()
}

// Uses aes to encrypt many values at once. This allows a substantial speedup (around 30%)
// compared to the naive approach.
#[allow(clippy::too_many_arguments)]
fn aes_encrypt_many<G>(
    message_1: u128,
    message_2: u128,
    message_3: u128,
    message_4: u128,
    message_5: u128,
    message_6: u128,
    message_7: u128,
    message_8: u128,
    cipher: &G,
) -> [u8; BYTES_PER_BATCH]
where
    G: BlockCipherEncrypt<BlockSize = U16>,
{
    let mut b1 = Block::from(message_1.to_ne_bytes());
    let mut b2 = Block::from(message_2.to_ne_bytes());
    let mut b3 = Block::from(message_3.to_ne_bytes());
    let mut b4 = Block::from(message_4.to_ne_bytes());
    let mut b5 = Block::from(message_5.to_ne_bytes());
    let mut b6 = Block::from(message_6.to_ne_bytes());
    let mut b7 = Block::from(message_7.to_ne_bytes());
    let mut b8 = Block::from(message_8.to_ne_bytes());

    cipher.encrypt_block(&mut b1);
    cipher.encrypt_block(&mut b2);
    cipher.encrypt_block(&mut b3);
    cipher.encrypt_block(&mut b4);
    cipher.encrypt_block(&mut b5);
    cipher.encrypt_block(&mut b6);
    cipher.encrypt_block(&mut b7);
    cipher.encrypt_block(&mut b8);

    let output_array: [[u8; BYTES_PER_AES_CALL]; AES_CALLS_PER_BATCH] = [
        b1.into(),
        b2.into(),
        b3.into(),
        b4.into(),
        b5.into(),
        b6.into(),
        b7.into(),
        b8.into(),
    ];

    unsafe { *{ output_array.as_ptr() as *const [u8; BYTES_PER_BATCH] } }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::generators::aes_ctr::block_cipher_generic_test;

    #[test]
    fn test_encrypt_one_message() {
        block_cipher_generic_test::test_fips197_c1_single_block::<Software128BlockCipher>();
    }

    #[test]
    fn test_encrypt_many_messages() {
        block_cipher_generic_test::test_fips197_c1_batch::<Software128BlockCipher>();
    }

    #[test]
    fn test_encrypt_one_message_256() {
        block_cipher_generic_test::test_fips197_c3_single_block::<Software256BlockCipher>();
    }

    #[test]
    fn test_encrypt_many_messages_256() {
        block_cipher_generic_test::test_fips197_c3_batch::<Software256BlockCipher>();
    }

    #[test]
    fn test_nist_vectors_256() {
        block_cipher_generic_test::test_nist_ecb_aes256_single_blocks::<Software256BlockCipher>();
    }

    #[test]
    fn test_nist_vectors_256_batch() {
        block_cipher_generic_test::test_nist_ecb_aes256_batch::<Software256BlockCipher>();
    }

    #[test]
    fn test_encrypt_many_matches_encrypt_one_256() {
        block_cipher_generic_test::test_batch_matches_single_aes256::<Software256BlockCipher>();
    }

    #[test]
    fn test_aes128_and_aes256_differ() {
        block_cipher_generic_test::test_aes128_and_aes256_differ::<
            Software128BlockCipher,
            Software256BlockCipher,
        >();
    }
}
