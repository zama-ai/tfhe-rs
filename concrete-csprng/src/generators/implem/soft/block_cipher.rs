use crate::generators::aes_ctr::{
    AesBlockCipher, AesIndex, AesKey, AES_CALLS_PER_BATCH, BYTES_PER_AES_CALL, BYTES_PER_BATCH,
};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

#[derive(Clone)]
pub struct SoftwareBlockCipher {
    // Aes structure
    aes: Aes128,
}

impl AesBlockCipher for SoftwareBlockCipher {
    fn new(key: AesKey) -> SoftwareBlockCipher {
        let key: [u8; BYTES_PER_AES_CALL] = key.0.to_ne_bytes();
        let key = GenericArray::clone_from_slice(&key[..]);
        let aes = Aes128::new(&key);
        SoftwareBlockCipher { aes }
    }

    fn generate_batch(&mut self, AesIndex(aes_ctr): AesIndex) -> [u8; BYTES_PER_BATCH] {
        aes_encrypt_many(
            aes_ctr,
            aes_ctr + 1,
            aes_ctr + 2,
            aes_ctr + 3,
            aes_ctr + 4,
            aes_ctr + 5,
            aes_ctr + 6,
            aes_ctr + 7,
            &self.aes,
        )
    }
}

// Uses aes to encrypt many values at once. This allows a substantial speedup (around 30%)
// compared to the naive approach.
#[allow(clippy::too_many_arguments)]
fn aes_encrypt_many(
    message_1: u128,
    message_2: u128,
    message_3: u128,
    message_4: u128,
    message_5: u128,
    message_6: u128,
    message_7: u128,
    message_8: u128,
    cipher: &Aes128,
) -> [u8; BYTES_PER_BATCH] {
    let mut b1 = GenericArray::clone_from_slice(&message_1.to_ne_bytes()[..]);
    let mut b2 = GenericArray::clone_from_slice(&message_2.to_ne_bytes()[..]);
    let mut b3 = GenericArray::clone_from_slice(&message_3.to_ne_bytes()[..]);
    let mut b4 = GenericArray::clone_from_slice(&message_4.to_ne_bytes()[..]);
    let mut b5 = GenericArray::clone_from_slice(&message_5.to_ne_bytes()[..]);
    let mut b6 = GenericArray::clone_from_slice(&message_6.to_ne_bytes()[..]);
    let mut b7 = GenericArray::clone_from_slice(&message_7.to_ne_bytes()[..]);
    let mut b8 = GenericArray::clone_from_slice(&message_8.to_ne_bytes()[..]);

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

    // Test vector for aes128, from the FIPS publication 197
    const CIPHER_KEY: u128 = u128::from_be(0x000102030405060708090a0b0c0d0e0f);
    const PLAINTEXT: u128 = u128::from_be(0x00112233445566778899aabbccddeeff);
    const CIPHERTEXT: u128 = u128::from_be(0x69c4e0d86a7b0430d8cdb78070b4c55a);

    #[test]
    fn test_encrypt_many_messages() {
        // Checks that encrypting many plaintext at the same time gives the correct output.
        let key: [u8; BYTES_PER_AES_CALL] = CIPHER_KEY.to_ne_bytes();
        let aes = Aes128::new(&GenericArray::from(key));
        let ciphertexts = aes_encrypt_many(
            PLAINTEXT, PLAINTEXT, PLAINTEXT, PLAINTEXT, PLAINTEXT, PLAINTEXT, PLAINTEXT, PLAINTEXT,
            &aes,
        );
        let ciphertexts: [u8; BYTES_PER_BATCH] = ciphertexts[..].try_into().unwrap();
        for i in 0..8 {
            assert_eq!(
                u128::from_ne_bytes(
                    ciphertexts[BYTES_PER_AES_CALL * i..BYTES_PER_AES_CALL * (i + 1)]
                        .try_into()
                        .unwrap()
                ),
                CIPHERTEXT
            );
        }
    }
}
