use crate::generators::aes_ctr::{AesBlockCipher, AesIndex, AesKey, BYTES_PER_BATCH};
use core::arch::aarch64::{
    uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u32, vdupq_n_u8, veorq_u8, vgetq_lane_u32,
    vreinterpretq_u32_u8, vreinterpretq_u8_u32,
};
use std::arch::is_aarch64_feature_detected;
use std::mem::transmute;

const RCONS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
const NUM_WORDS_IN_KEY: usize = 4;
const NUM_ROUNDS: usize = 10;
const NUM_ROUND_KEYS: usize = NUM_ROUNDS + 1;

/// An aes block cipher implementation which uses `neon` and `aes` instructions.
#[derive(Clone)]
pub struct ArmAesBlockCipher {
    round_keys: [uint8x16_t; NUM_ROUND_KEYS],
}

impl AesBlockCipher for ArmAesBlockCipher {
    fn new(key: AesKey) -> ArmAesBlockCipher {
        let aes_detected = is_aarch64_feature_detected!("aes");
        let neon_detected = is_aarch64_feature_detected!("neon");

        if !(aes_detected && neon_detected) {
            panic!(
                "The ArmAesBlockCipher requires both aes and neon aarch64 CPU features.\n\
                aes feature available: {}\nneon feature available: {}\n.",
                aes_detected, neon_detected
            )
        }

        let round_keys = unsafe { generate_round_keys(key) };
        ArmAesBlockCipher { round_keys }
    }

    fn generate_batch(&mut self, AesIndex(aes_ctr): AesIndex) -> [u8; BYTES_PER_BATCH] {
        #[target_feature(enable = "aes,neon")]
        unsafe fn implementation(
            this: &ArmAesBlockCipher,
            AesIndex(aes_ctr): AesIndex,
        ) -> [u8; BYTES_PER_BATCH] {
            let mut output = [0u8; BYTES_PER_BATCH];
            // We want 128 bytes of output, the ctr gives 128 bit message (16 bytes)
            for (i, out) in output.chunks_exact_mut(16).enumerate() {
                // Safe because we prevent the user from creating the Generator
                // on non-supported hardware
                let encrypted = encrypt(aes_ctr + (i as u128), &this.round_keys);
                out.copy_from_slice(&encrypted.to_ne_bytes());
            }
            output
        }
        // SAFETY: we checked for aes and neon availability in `Self::new`
        unsafe { implementation(self, AesIndex(aes_ctr)) }
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
unsafe fn generate_round_keys(key: AesKey) -> [uint8x16_t; NUM_ROUND_KEYS] {
    let mut round_keys: [uint8x16_t; NUM_ROUND_KEYS] = std::mem::zeroed();
    round_keys[0] = u128_to_uint8x16_t(key.0);

    let words = std::slice::from_raw_parts_mut(
        round_keys.as_mut_ptr() as *mut u32,
        NUM_ROUND_KEYS * NUM_WORDS_IN_KEY,
    );

    debug_assert_eq!(words.len(), 44);

    // Skip the words of the first key, its already done
    for i in NUM_WORDS_IN_KEY..words.len() {
        if (i % NUM_WORDS_IN_KEY) == 0 {
            words[i] = words[i - NUM_WORDS_IN_KEY]
                ^ sub_word(words[i - 1]).rotate_right(8)
                ^ RCONS[(i / NUM_WORDS_IN_KEY) - 1];
        } else {
            words[i] = words[i - NUM_WORDS_IN_KEY] ^ words[i - 1];
        }
        // Note: there is also a special thing to do when
        // i mod SElf::NUM_WORDS_IN_KEY == 4 but it cannot happen on 128 bits keys
    }

    round_keys
}

/// Encrypts a 128-bit message
///
/// # SAFETY
///
/// You must make sure the CPU's arch is`aarch64` and has
/// `neon` and `aes` features.
#[inline(always)]
unsafe fn encrypt(message: u128, keys: &[uint8x16_t; NUM_ROUND_KEYS]) -> u128 {
    // Notes:
    // According the [ARM Manual](https://developer.arm.com/documentation/ddi0487/gb/):
    // `vaeseq_u8` is the following AES operations:
    //      1. AddRoundKey (XOR)
    //      2. ShiftRows
    //      3. SubBytes
    // `vaesmcq_u8` is MixColumns
    let mut data: uint8x16_t = u128_to_uint8x16_t(message);

    for &key in keys.iter().take(NUM_ROUNDS - 1) {
        data = vaesmcq_u8(vaeseq_u8(data, key));
    }

    data = vaeseq_u8(data, keys[NUM_ROUNDS - 1]);
    data = veorq_u8(data, keys[NUM_ROUND_KEYS - 1]);

    uint8x16_t_to_u128(data)
}

#[cfg(test)]
mod test {
    use super::*;

    // Test vector for aes128, from the FIPS publication 197
    const CIPHER_KEY: u128 = u128::from_be(0x000102030405060708090a0b0c0d0e0f);
    const KEY_SCHEDULE: [u128; 11] = [
        u128::from_be(0x000102030405060708090a0b0c0d0e0f),
        u128::from_be(0xd6aa74fdd2af72fadaa678f1d6ab76fe),
        u128::from_be(0xb692cf0b643dbdf1be9bc5006830b3fe),
        u128::from_be(0xb6ff744ed2c2c9bf6c590cbf0469bf41),
        u128::from_be(0x47f7f7bc95353e03f96c32bcfd058dfd),
        u128::from_be(0x3caaa3e8a99f9deb50f3af57adf622aa),
        u128::from_be(0x5e390f7df7a69296a7553dc10aa31f6b),
        u128::from_be(0x14f9701ae35fe28c440adf4d4ea9c026),
        u128::from_be(0x47438735a41c65b9e016baf4aebf7ad2),
        u128::from_be(0x549932d1f08557681093ed9cbe2c974e),
        u128::from_be(0x13111d7fe3944a17f307a78b4d2b30c5),
    ];
    const PLAINTEXT: u128 = u128::from_be(0x00112233445566778899aabbccddeeff);
    const CIPHERTEXT: u128 = u128::from_be(0x69c4e0d86a7b0430d8cdb78070b4c55a);

    #[test]
    fn test_generate_key_schedule() {
        // Checks that the round keys are correctly generated from the sample key from FIPS
        let key = AesKey(CIPHER_KEY);
        let keys = unsafe { generate_round_keys(key) };
        for (expected, actual) in KEY_SCHEDULE.iter().zip(keys.iter()) {
            assert_eq!(*expected, uint8x16_t_to_u128(*actual));
        }
    }

    #[test]
    fn test_encrypt_message() {
        // Checks that encrypting many plaintext at the same time gives the correct output.
        let message = PLAINTEXT;
        let key = AesKey(CIPHER_KEY);
        let keys = unsafe { generate_round_keys(key) };
        let ciphertext = unsafe { encrypt(message, &keys) };
        assert_eq!(CIPHERTEXT, ciphertext);
    }
}
