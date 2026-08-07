use crate::generators::aes_ctr::{
    Aes128Key, Aes256Key, AesBlockCipher, AES_128_NUM_ROUND_KEYS, AES_256_NUM_ROUND_KEYS,
    AES_CALLS_PER_BATCH, BYTES_PER_AES_CALL, BYTES_PER_BATCH,
};
use core::arch::aarch64::{
    uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u32, vdupq_n_u8, veorq_u8, vgetq_lane_u32,
    vreinterpretq_u32_u8, vreinterpretq_u8_u32,
};
use std::arch::is_aarch64_feature_detected;
use std::mem::transmute;

#[derive(Copy, Clone)]
pub struct Arm;

impl crate::generators::AesBackend for Arm {
    type Aes128BlockCipher = ArmAes128BlockCipher;

    type Aes256BlockCipher = ArmAes256BlockCipher;
}

trait ArmKey: Sized {
    type Array;

    fn generate_round_keys(self) -> Self::Array {
        let aes_detected = is_aarch64_feature_detected!("aes");
        let neon_detected = is_aarch64_feature_detected!("neon");

        if !(aes_detected && neon_detected) {
            panic!(
                "The arm64 based block cipher requires both aes and neon aarch64 CPU features.\n\
                aes feature available: {aes_detected}\nneon feature available: {neon_detected}\n\
                Please consider enabling the SoftwareRandomGenerator with the `software-prng` feature",
            )
        }

        // SAFETY: we checked for aes and sse2 availability
        unsafe { self.unchecked_generate_round_keys() }
    }

    unsafe fn unchecked_generate_round_keys(self) -> Self::Array;
}

impl ArmKey for Aes128Key {
    type Array = [uint8x16_t; AES_128_NUM_ROUND_KEYS];

    unsafe fn unchecked_generate_round_keys(self) -> Self::Array {
        aes_key_schedule(self.0.to_ne_bytes())
    }
}

impl ArmKey for Aes256Key {
    type Array = [uint8x16_t; AES_256_NUM_ROUND_KEYS];

    unsafe fn unchecked_generate_round_keys(self) -> Self::Array {
        aes_key_schedule(self.0)
    }
}

/// An aes block cipher implementation which uses `neon` and `aes` instructions.
///
/// Not re-exported: only the [`ArmAes128BlockCipher`] and [`ArmAes256BlockCipher`] so that
/// users cannot potentially use this type with a bad `N`.
#[derive(Clone)]
pub struct ArmAesBlockCipher<const N: usize> {
    round_keys: [uint8x16_t; N],
}

/// The aarch64 Aes-128 block cipher.
pub type ArmAes128BlockCipher = ArmAesBlockCipher<AES_128_NUM_ROUND_KEYS>;

/// The aarch64 Aes-256 block cipher.
pub type ArmAes256BlockCipher = ArmAesBlockCipher<AES_256_NUM_ROUND_KEYS>;

// Shared by both `AesBlockCipher` impls below, which otherwise differ only in their `Key`.
impl<const N: usize> ArmAesBlockCipher<N> {
    fn encrypt_batch(&self, data: [u128; AES_CALLS_PER_BATCH]) -> [u8; BYTES_PER_BATCH] {
        // SAFETY: we checked for aes and neon availability in `Self::new`
        unsafe { generate_batch(data, &self.round_keys) }
    }

    fn encrypt_next(&self, data: u128) -> [u8; BYTES_PER_AES_CALL] {
        // SAFETY: we checked for aes and neon availability in `Self::new`
        unsafe { generate_next(data, &self.round_keys) }
    }
}

impl AesBlockCipher for ArmAes128BlockCipher {
    type Key = Aes128Key;

    fn new(key: Self::Key) -> Self {
        Self {
            round_keys: key.generate_round_keys(),
        }
    }

    fn generate_batch(&mut self, data: [u128; AES_CALLS_PER_BATCH]) -> [u8; BYTES_PER_BATCH] {
        self.encrypt_batch(data)
    }

    fn generate_next(&mut self, data: u128) -> [u8; BYTES_PER_AES_CALL] {
        self.encrypt_next(data)
    }
}

impl AesBlockCipher for ArmAes256BlockCipher {
    type Key = Aes256Key;

    fn new(key: Self::Key) -> Self {
        Self {
            round_keys: key.generate_round_keys(),
        }
    }

    fn generate_batch(&mut self, data: [u128; AES_CALLS_PER_BATCH]) -> [u8; BYTES_PER_BATCH] {
        self.encrypt_batch(data)
    }

    fn generate_next(&mut self, data: u128) -> [u8; BYTES_PER_AES_CALL] {
        self.encrypt_next(data)
    }
}

/// Does the AES SubWord operation for the Key Expansion step
///
/// # SAFETY
///
/// You must make sure the CPU's arch is`aarch64` and has
/// `neon` and `aes` features.
#[inline(always)]
unsafe fn sub_word(word: u32) -> u32 {
    let data = vreinterpretq_u8_u32(vdupq_n_u32(word));
    let zero_key = vdupq_n_u8(0u8);
    let temp = vaeseq_u8(data, zero_key);
    // vaeseq_u8 does SubBytes(ShiftRow(XOR(data, key))
    // But because we used a zero aes key,the XOR did not alter data
    // We now have temp = SubBytes(ShiftRow(data))

    // Since in AES ShiftRow operation, the first row is not shifted
    // We can just get that one to have our SubWord(word) result
    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(temp))
}

#[inline(always)]
fn uint8x16_t_to_u128(input: uint8x16_t) -> u128 {
    unsafe { transmute(input) }
}

#[inline(always)]
fn u128_to_uint8x16_t(input: u128) -> uint8x16_t {
    unsafe { transmute(input) }
}

#[target_feature(enable = "aes,neon")]
unsafe fn aes_key_schedule<const S: usize, const R: usize>(
    aes_key_bytes: [u8; S],
) -> [uint8x16_t; R] {
    const {
        assert!(
            (S == 16 && R == AES_128_NUM_ROUND_KEYS) || (S == 32 && R == AES_256_NUM_ROUND_KEYS),
            "AES key length and round key count must match"
        )
    };
    const RCONS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    // 'words' are 32 bit, since we have bytes: 32/8=4
    let num_words_in_key = S / 4;
    // Whatever the key size, a round key is always 128 bits, that is 4 words
    const NUM_WORDS_IN_ROUND_KEY: usize = 4;

    let mut round_keys: [uint8x16_t; R] = std::mem::zeroed();
    let words = std::slice::from_raw_parts_mut(
        round_keys.as_mut_ptr() as *mut u32,
        R * NUM_WORDS_IN_ROUND_KEY,
    );

    for i in 0..num_words_in_key {
        let bytes = [
            aes_key_bytes[i * 4],
            aes_key_bytes[(i * 4) + 1],
            aes_key_bytes[(i * 4) + 2],
            aes_key_bytes[(i * 4) + 3],
        ];
        words[i] = u32::from_ne_bytes(bytes)
    }
    // Skip the words of the first key, its already done
    for i in num_words_in_key..words.len() {
        if (i % num_words_in_key) == 0 {
            words[i] = words[i - num_words_in_key]
                ^ sub_word(words[i - 1]).rotate_right(8)
                ^ RCONS[(i / num_words_in_key) - 1];
        } else if num_words_in_key > 6 && (i % num_words_in_key) == 4 {
            words[i] = words[i - num_words_in_key] ^ sub_word(words[i - 1]);
        } else {
            words[i] = words[i - num_words_in_key] ^ words[i - 1];
        }
    }

    round_keys
}

/// Encrypts a batch of  128-bit message
///
/// # SAFETY
///
/// You must make sure the CPU's arch is`aarch64` and has
/// `neon` and `aes` features.
#[target_feature(enable = "aes,neon")]
unsafe fn generate_batch<const N: usize>(
    messages: [u128; AES_CALLS_PER_BATCH],
    round_keys: &[uint8x16_t; N],
) -> [u8; BYTES_PER_BATCH] {
    let mut output = [0u8; BYTES_PER_BATCH];
    // We want 128 bytes of output, the ctr gives 128 bit message (16 bytes)
    for (message, out) in messages.iter().copied().zip(output.as_chunks_mut::<16>().0) {
        let encrypted = encrypt(message, round_keys);
        out.copy_from_slice(&encrypted.to_ne_bytes());
    }
    output
}

/// Encrypts a single 128-bit message
///
/// We have this, so that we call the encrypt function in a context where target_features are
/// enabled
///
/// # SAFETY
///
/// You must make sure the CPU's arch is`aarch64` and has
/// `neon` and `aes` features.
#[target_feature(enable = "aes,neon")]
unsafe fn generate_next<const N: usize>(
    message: u128,
    round_keys: &[uint8x16_t; N],
) -> [u8; BYTES_PER_AES_CALL] {
    encrypt(message, round_keys).to_ne_bytes()
}

/// Encrypts a 128-bit message
///
/// # SAFETY
///
/// You must make sure the CPU's arch is`aarch64` and has
/// `neon` and `aes` features.
#[inline(always)]
unsafe fn encrypt<const N: usize>(message: u128, keys: &[uint8x16_t; N]) -> u128 {
    // Notes:
    // According the [ARM Manual](https://developer.arm.com/documentation/ddi0487/gb/):
    // `vaeseq_u8` is the following AES operations:
    //      1. AddRoundKey (XOR)
    //      2. SubBytes
    //      3. ShiftRows
    // `vaesmcq_u8` is MixColumns
    let mut data: uint8x16_t = u128_to_uint8x16_t(message);

    for &key in keys.iter().take(N - 2) {
        data = vaesmcq_u8(vaeseq_u8(data, key));
    }

    data = vaeseq_u8(data, keys[N - 2]);
    data = veorq_u8(data, keys[N - 1]);

    uint8x16_t_to_u128(data)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::generators::aes_ctr::block_cipher_generic_test;

    #[test]
    fn test_generate_key_schedule() {
        block_cipher_generic_test::test_key_schedule_128(|key| {
            key.generate_round_keys().map(uint8x16_t_to_u128)
        });
    }

    #[test]
    fn test_generate_key_schedule_256() {
        block_cipher_generic_test::test_key_schedule_256(|key| {
            key.generate_round_keys().map(uint8x16_t_to_u128)
        });
    }

    #[test]
    fn test_encrypt_one_message() {
        block_cipher_generic_test::test_fips197_c1_single_block::<ArmAes128BlockCipher>();
    }

    #[test]
    fn test_encrypt_many_messages() {
        block_cipher_generic_test::test_fips197_c1_batch::<ArmAes128BlockCipher>();
    }

    #[test]
    fn test_encrypt_one_message_256() {
        block_cipher_generic_test::test_fips197_c3_single_block::<ArmAes256BlockCipher>();
    }

    #[test]
    fn test_encrypt_many_messages_256() {
        block_cipher_generic_test::test_fips197_c3_batch::<ArmAes256BlockCipher>();
    }

    #[test]
    fn test_nist_vectors_256() {
        block_cipher_generic_test::test_nist_ecb_aes256_single_blocks::<ArmAes256BlockCipher>();
    }

    #[test]
    fn test_nist_vectors_256_batch() {
        block_cipher_generic_test::test_nist_ecb_aes256_batch::<ArmAes256BlockCipher>();
    }

    #[test]
    fn test_encrypt_many_matches_encrypt_one_256() {
        block_cipher_generic_test::test_batch_matches_single_aes256::<ArmAes256BlockCipher>();
    }

    #[test]
    fn test_aes128_and_aes256_differ() {
        block_cipher_generic_test::test_aes128_and_aes256_differ::<
            ArmAes128BlockCipher,
            ArmAes256BlockCipher,
        >();
    }
}
