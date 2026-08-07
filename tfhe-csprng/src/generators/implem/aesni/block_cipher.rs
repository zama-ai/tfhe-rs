use crate::generators::aes_ctr::{
    Aes128Key, Aes256Key, AesBlockCipher, AES_CALLS_PER_BATCH, BYTES_PER_AES_CALL, BYTES_PER_BATCH,
};
use std::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128, _mm_shuffle_epi32,
    _mm_slli_si128, _mm_store_si128, _mm_xor_si128,
};
use std::mem::transmute;

#[derive(Copy, Clone)]
pub struct Aesni;

impl crate::generators::AesBackend for Aesni {
    type Aes128BlockCipher = Aesni128BlockCipher;

    type Aes256BlockCipher = Aesni256BlockCipher;
}

trait AesniKey: Sized {
    type Array;

    fn generate_round_keys(self) -> Self::Array {
        let aes_detected = is_x86_feature_detected!("aes");
        let sse2_detected = is_x86_feature_detected!("sse2");

        if !(aes_detected && sse2_detected) {
            panic!(
                "The aesni based block ciphers requires both aes and sse2 x86 CPU features.\n\
                aes feature available: {aes_detected}\nsse2 feature available: {sse2_detected}\n\
                Please consider enabling the SoftwareRandomGenerator with the `software-prng` feature",
            )
        }

        // SAFETY: we checked for aes and sse2 availability
        unsafe { self.unchecked_generate_round_keys() }
    }

    unsafe fn unchecked_generate_round_keys(self) -> Self::Array;
}

impl AesniKey for Aes128Key {
    type Array = [__m128i; 11];

    unsafe fn unchecked_generate_round_keys(self) -> Self::Array {
        generate_round_keys_128(self)
    }
}

impl AesniKey for Aes256Key {
    type Array = [__m128i; 15];

    unsafe fn unchecked_generate_round_keys(self) -> Self::Array {
        generate_round_keys_256(self)
    }
}

/// An aes block cipher implementation which uses `aesni` instructions.
///
/// Not re-exported: only the [`Aesni128BlockCipher`] and [`Aesni256BlockCipher`] so that
/// users cannot potentially use this type with a bad `N`.
#[derive(Clone)]
pub struct AesniBlockCipher<const N: usize> {
    // The set of round keys used for the aes encryption
    round_keys: [__m128i; N],
}

/// The aesni Aes-128 block cipher.
pub type Aesni128BlockCipher = AesniBlockCipher<11>;

/// The aesni Aes-256 block cipher.
pub type Aesni256BlockCipher = AesniBlockCipher<15>;

// Shared by both `AesBlockCipher` impls below, which otherwise differ only in their `Key`.
impl<const N: usize> AesniBlockCipher<N> {
    fn encrypt_batch(&self, data: [u128; AES_CALLS_PER_BATCH]) -> [u8; BYTES_PER_BATCH] {
        // SAFETY: we checked for aes and sse2 availability in `Self::new`
        unsafe { generate_batch_implementation(&self.round_keys, data) }
    }

    fn encrypt_next(&self, data: u128) -> [u8; BYTES_PER_AES_CALL] {
        // SAFETY: we checked for aes and sse2 availability in `Self::new`
        unsafe { generate_next_implementation(&self.round_keys, data) }
    }
}

impl AesBlockCipher for Aesni128BlockCipher {
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

impl AesBlockCipher for Aesni256BlockCipher {
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

#[target_feature(enable = "sse2,aes")]
unsafe fn generate_round_keys_128(key: Aes128Key) -> [__m128i; 11] {
    let key = u128_to_si128(key.0);
    let mut keys: [__m128i; 11] = [u128_to_si128(0); 11];
    aes_128_key_expansion(key, &mut keys);
    keys
}

#[target_feature(enable = "sse2,aes")]
unsafe fn generate_batch_implementation<const N: usize>(
    round_keys: &[__m128i; N],
    data: [u128; AES_CALLS_PER_BATCH],
) -> [u8; BYTES_PER_BATCH] {
    si128arr_to_u8arr(aes_encrypt_many(
        u128_to_si128(data[0]),
        u128_to_si128(data[1]),
        u128_to_si128(data[2]),
        u128_to_si128(data[3]),
        u128_to_si128(data[4]),
        u128_to_si128(data[5]),
        u128_to_si128(data[6]),
        u128_to_si128(data[7]),
        round_keys,
    ))
}

// Like `generate_batch_implementation`, this exists so that the aes intrinsics are expanded in a
// context where the `aes` feature is enabled. Calling `aes_encrypt_one` straight from the trait
// method instead leaves the round loop rolled, with an out-of-line call per round, on any build
// that does not enable `aes` crate-wide (e.g. without `-C target-cpu=native`).
#[target_feature(enable = "sse2,aes")]
unsafe fn generate_next_implementation<const N: usize>(
    round_keys: &[__m128i; N],
    data: u128,
) -> [u8; BYTES_PER_AES_CALL] {
    transmute(aes_encrypt_one(u128_to_si128(data), round_keys))
}

#[inline(always)]
fn aes_encrypt_one<const N: usize>(message: __m128i, keys: &[__m128i; N]) -> __m128i {
    const { assert!(N == 11 || N == 15, "invalid AES round key count") };
    unsafe {
        let mut tmp_1 = _mm_xor_si128(message, keys[0]);

        for key in keys.iter().take(N - 1).skip(1) {
            tmp_1 = _mm_aesenc_si128(tmp_1, *key);
        }

        _mm_aesenclast_si128(tmp_1, keys[N - 1])
    }
}

// Uses aes to encrypt many values at once. This allows a substantial speedup (around 30%)
// compared to the naive approach.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn aes_encrypt_many<const N: usize>(
    message_1: __m128i,
    message_2: __m128i,
    message_3: __m128i,
    message_4: __m128i,
    message_5: __m128i,
    message_6: __m128i,
    message_7: __m128i,
    message_8: __m128i,
    keys: &[__m128i; N],
) -> [__m128i; 8] {
    const { assert!(N == 11 || N == 15, "invalid AES round key count") };
    unsafe {
        let mut tmp_1 = _mm_xor_si128(message_1, keys[0]);
        let mut tmp_2 = _mm_xor_si128(message_2, keys[0]);
        let mut tmp_3 = _mm_xor_si128(message_3, keys[0]);
        let mut tmp_4 = _mm_xor_si128(message_4, keys[0]);
        let mut tmp_5 = _mm_xor_si128(message_5, keys[0]);
        let mut tmp_6 = _mm_xor_si128(message_6, keys[0]);
        let mut tmp_7 = _mm_xor_si128(message_7, keys[0]);
        let mut tmp_8 = _mm_xor_si128(message_8, keys[0]);

        for key in keys.iter().take(N - 1).skip(1) {
            tmp_1 = _mm_aesenc_si128(tmp_1, *key);
            tmp_2 = _mm_aesenc_si128(tmp_2, *key);
            tmp_3 = _mm_aesenc_si128(tmp_3, *key);
            tmp_4 = _mm_aesenc_si128(tmp_4, *key);
            tmp_5 = _mm_aesenc_si128(tmp_5, *key);
            tmp_6 = _mm_aesenc_si128(tmp_6, *key);
            tmp_7 = _mm_aesenc_si128(tmp_7, *key);
            tmp_8 = _mm_aesenc_si128(tmp_8, *key);
        }

        tmp_1 = _mm_aesenclast_si128(tmp_1, keys[N - 1]);
        tmp_2 = _mm_aesenclast_si128(tmp_2, keys[N - 1]);
        tmp_3 = _mm_aesenclast_si128(tmp_3, keys[N - 1]);
        tmp_4 = _mm_aesenclast_si128(tmp_4, keys[N - 1]);
        tmp_5 = _mm_aesenclast_si128(tmp_5, keys[N - 1]);
        tmp_6 = _mm_aesenclast_si128(tmp_6, keys[N - 1]);
        tmp_7 = _mm_aesenclast_si128(tmp_7, keys[N - 1]);
        tmp_8 = _mm_aesenclast_si128(tmp_8, keys[N - 1]);

        [tmp_1, tmp_2, tmp_3, tmp_4, tmp_5, tmp_6, tmp_7, tmp_8]
    }
}

#[inline(always)]
unsafe fn aes_key_fold(mut temp1: __m128i, temp2: __m128i) -> __m128i {
    let mut temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    _mm_xor_si128(temp1, temp2)
}

fn aes_128_assist(temp1: __m128i, temp2: __m128i) -> __m128i {
    let mut temp2 = temp2;
    let mut temp1 = temp1;
    unsafe {
        temp2 = _mm_shuffle_epi32(temp2, 0xff);
        temp1 = aes_key_fold(temp1, temp2);
    }
    temp1
}

#[inline(always)]
fn aes_128_key_expansion(key: __m128i, keys: &mut [__m128i; 11]) {
    let (mut temp1, mut temp2): (__m128i, __m128i);
    temp1 = key;
    unsafe {
        _mm_store_si128(keys.as_mut_ptr(), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(1), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(2), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(3), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(4), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(5), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(6), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(7), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(8), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(9), temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
        temp1 = aes_128_assist(temp1, temp2);
        _mm_store_si128(keys.as_mut_ptr().offset(10), temp1);
    }
}

fn aes_256_assist_1(temp1: __m128i, temp2: __m128i) -> __m128i {
    aes_128_assist(temp1, temp2)
}

fn aes_256_assist_2(temp1: __m128i, temp3: __m128i) -> __m128i {
    unsafe {
        let temp4 = _mm_aeskeygenassist_si128(temp1, 0x0);
        let temp2 = _mm_shuffle_epi32(temp4, 0xaa);
        aes_key_fold(temp3, temp2)
    }
}

#[target_feature(enable = "sse2,aes")]
unsafe fn generate_round_keys_256(key: Aes256Key) -> [__m128i; 15] {
    let mut keys: [__m128i; 15] = [u128_to_si128(0); 15];

    let first_half: [u8; 16] = key.0[..16].try_into().expect("infallible");
    let second_half: [u8; 16] = key.0[16..].try_into().expect("infallible");

    let mut temp1: __m128i = transmute(first_half);
    let mut temp2: __m128i;
    let mut temp3: __m128i = transmute(second_half);

    keys[0] = temp1;
    keys[1] = temp3;

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
    temp1 = aes_256_assist_1(temp1, temp2);
    keys[2] = temp1;
    temp3 = aes_256_assist_2(temp1, temp3);
    keys[3] = temp3;

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
    temp1 = aes_256_assist_1(temp1, temp2);
    keys[4] = temp1;
    temp3 = aes_256_assist_2(temp1, temp3);
    keys[5] = temp3;

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
    temp1 = aes_256_assist_1(temp1, temp2);
    keys[6] = temp1;
    temp3 = aes_256_assist_2(temp1, temp3);
    keys[7] = temp3;

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
    temp1 = aes_256_assist_1(temp1, temp2);
    keys[8] = temp1;
    temp3 = aes_256_assist_2(temp1, temp3);
    keys[9] = temp3;

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
    temp1 = aes_256_assist_1(temp1, temp2);
    keys[10] = temp1;
    temp3 = aes_256_assist_2(temp1, temp3);
    keys[11] = temp3;

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
    temp1 = aes_256_assist_1(temp1, temp2);
    keys[12] = temp1;
    temp3 = aes_256_assist_2(temp1, temp3);
    keys[13] = temp3;

    // The last round only needs `aes_256_assist_1`: the schedule is 60 words (15 round keys), so
    // it stops on the `i % 8 == 0` branch. A trailing `aes_256_assist_2` would compute a 16th key.
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
    temp1 = aes_256_assist_1(temp1, temp2);
    keys[14] = temp1;

    keys
}

#[inline(always)]
fn u128_to_si128(input: u128) -> __m128i {
    unsafe { transmute(input) }
}

#[allow(unused)] // to please clippy when tests are not activated
fn si128_to_u128(input: __m128i) -> u128 {
    unsafe { transmute(input) }
}

#[inline(always)]
fn si128arr_to_u8arr(input: [__m128i; 8]) -> [u8; BYTES_PER_BATCH] {
    unsafe { transmute(input) }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::generators::aes_ctr::block_cipher_generic_test;

    // SAFETY (both closures): the aesni module is only compiled in on x86_64, and the round key
    // generation is otherwise guarded by the cpu feature check in `AesniKey::generate_round_keys`.

    #[test]
    fn test_generate_key_schedule() {
        block_cipher_generic_test::test_key_schedule_128(|key| {
            unsafe { generate_round_keys_128(key) }.map(si128_to_u128)
        });
    }

    #[test]
    fn test_generate_key_schedule_256() {
        block_cipher_generic_test::test_key_schedule_256(|key| {
            unsafe { generate_round_keys_256(key) }.map(si128_to_u128)
        });
    }

    #[test]
    fn test_encrypt_one_message() {
        block_cipher_generic_test::test_fips197_c1_single_block::<Aesni128BlockCipher>();
    }

    #[test]
    fn test_encrypt_many_messages() {
        block_cipher_generic_test::test_fips197_c1_batch::<Aesni128BlockCipher>();
    }

    #[test]
    fn test_encrypt_one_message_256() {
        block_cipher_generic_test::test_fips197_c3_single_block::<Aesni256BlockCipher>();
    }

    #[test]
    fn test_encrypt_many_messages_256() {
        block_cipher_generic_test::test_fips197_c3_batch::<Aesni256BlockCipher>();
    }

    #[test]
    fn test_nist_vectors_256() {
        block_cipher_generic_test::test_nist_ecb_aes256_single_blocks::<Aesni256BlockCipher>();
    }

    #[test]
    fn test_nist_vectors_256_batch() {
        block_cipher_generic_test::test_nist_ecb_aes256_batch::<Aesni256BlockCipher>();
    }

    #[test]
    fn test_encrypt_many_matches_encrypt_one_256() {
        block_cipher_generic_test::test_batch_matches_single_aes256::<Aesni256BlockCipher>();
    }

    #[test]
    fn test_aes128_and_aes256_differ() {
        block_cipher_generic_test::test_aes128_and_aes256_differ::<
            Aesni128BlockCipher,
            Aesni256BlockCipher,
        >();
    }
}
