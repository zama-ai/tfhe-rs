use crate::generators::aes_ctr::{AES_CALLS_PER_BATCH, BYTES_PER_AES_CALL, BYTES_PER_BATCH};

/// Represents a key used in the AES 128 block cipher.
///
/// The u128 endianness should be ignored by implementations and the u128 should be seen as a simple
/// [u8; 16].
///
/// Therefore, except when loading the key from a [`Seed`](`crate::seeders::Seed`), whose bytes
/// needs to be loaded with [u128::from_le] (to keep consistency of the loaded bytes across systems
/// endianness), the rest of the code should use the [`Aes128Key`] with native endian ordering such
/// that the internal u128 is equivalent to [u8; 16].
#[derive(Clone, Copy, Debug)]
pub struct Aes128Key(pub(crate) u128);

impl Aes128Key {
    /// Builds an [`Aes128Key`] from a `u128`.
    ///
    /// The `u128` is interpreted in native endian ordering, so that its in-memory bytes are
    /// equivalent to a `[u8; 16]` (see the type-level documentation). Callers that load a key from
    /// raw bytes must therefore arrange them to match the native byte order beforehand.
    pub const fn new(key: u128) -> Self {
        Self(key)
    }
}

/// Key for AES 256 Block cipher
pub struct Aes256Key(pub(crate) [u8; 32]);

impl Aes256Key {
    pub const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
}

/// A trait for AES block ciphers.
///
/// Note:
/// -----
///
/// The block cipher is used in a batched manner (to reduce amortized cost on special hardware).
/// For this reason we only expose a `generate_batch` method.
pub trait AesBlockCipher: Clone + Send + Sync {
    type Key;

    /// Instantiate a new generator from a secret key.
    fn new(key: Self::Key) -> Self;
    /// Generates the batch corresponding to the given index.
    fn generate_batch(&mut self, data: [u128; AES_CALLS_PER_BATCH]) -> [u8; BYTES_PER_BATCH];
    /// Generate next bytes
    fn generate_next(&mut self, data: u128) -> [u8; BYTES_PER_AES_CALL];
}

pub trait Aes128BlockCipher: AesBlockCipher<Key = Aes128Key> {}
impl<T> Aes128BlockCipher for T where T: AesBlockCipher<Key = Aes128Key> {}
pub trait Aes256BlockCipher: AesBlockCipher<Key = Aes256Key> {}
impl<T> Aes256BlockCipher for T where T: AesBlockCipher<Key = Aes256Key> {}

/// Known answer tests shared by every block cipher backend.
#[cfg(test)]
#[allow(unused)] // to please clippy when tests are not activated
pub mod block_cipher_generic_test {
    use super::*;
    use crate::generators::aes_ctr::{AES_128_NUM_ROUND_KEYS, AES_256_NUM_ROUND_KEYS};

    // Test vector for aes128, from appendix C.1 of the FIPS publication 197
    pub const KEY_128: u128 = u128::from_be(0x000102030405060708090a0b0c0d0e0f);
    pub const KEY_SCHEDULE_128: [u128; AES_128_NUM_ROUND_KEYS] = [
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
    /// Plaintext of both the C.1 (aes128) and C.3 (aes256) vectors.
    pub const PLAINTEXT: u128 = u128::from_be(0x00112233445566778899aabbccddeeff);
    pub const CIPHERTEXT_128: u128 = u128::from_be(0x69c4e0d86a7b0430d8cdb78070b4c55a);

    // Test vector for aes256, from appendix C.3 of the FIPS publication 197
    pub const KEY_256: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    pub const KEY_SCHEDULE_256: [u128; AES_256_NUM_ROUND_KEYS] = [
        u128::from_be(0x000102030405060708090a0b0c0d0e0f),
        u128::from_be(0x101112131415161718191a1b1c1d1e1f),
        u128::from_be(0xa573c29fa176c498a97fce93a572c09c),
        u128::from_be(0x1651a8cd0244beda1a5da4c10640bade),
        u128::from_be(0xae87dff00ff11b68a68ed5fb03fc1567),
        u128::from_be(0x6de1f1486fa54f9275f8eb5373b8518d),
        u128::from_be(0xc656827fc9a799176f294cec6cd5598b),
        u128::from_be(0x3de23a75524775e727bf9eb45407cf39),
        u128::from_be(0x0bdc905fc27b0948ad5245a4c1871c2f),
        u128::from_be(0x45f5a66017b2d387300d4d33640a820a),
        u128::from_be(0x7ccff71cbeb4fe5413e6bbf0d261a7df),
        u128::from_be(0xf01afafee7a82979d7a5644ab3afe640),
        u128::from_be(0x2541fe719bf500258813bbd55a721c0a),
        u128::from_be(0x4e5a6699a9f24fe07e572baacdf8cdea),
        u128::from_be(0x24fc79ccbf0979e9371ac23c6d68de36),
    ];
    pub const CIPHERTEXT_256: u128 = u128::from_be(0x8ea2b7ca516745bfeafc49904b496089);

    // ECB-AES256 test vectors from appendix F.1.5 of NIST SP 800-38A. Uses a different (less
    // structured) key than the FIPS C.3 vector above, and four distinct plaintext blocks.
    pub const NIST_KEY_256: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ];
    pub const NIST_BLOCKS_256: [(u128, u128); 4] = [
        (
            u128::from_be(0x6bc1bee22e409f96e93d7e117393172a),
            u128::from_be(0xf3eed1bdb5d2a03c064b5a7e3db181f8),
        ),
        (
            u128::from_be(0xae2d8a571e03ac9c9eb76fac45af8e51),
            u128::from_be(0x591ccb10d410ed26dc5ba74a31362870),
        ),
        (
            u128::from_be(0x30c81c46a35ce411e5fbc1191a0a52ef),
            u128::from_be(0xb6ed21b99ca6f4f9f153e7b1beafed1d),
        ),
        (
            u128::from_be(0xf69f2445df4f9b17ad2b417be66c3710),
            u128::from_be(0x23304b7a39f9f3ff067d8d8f9e24ecc7),
        ),
    ];

    /// Eight pairwise-distinct blocks, so that a lane mix-up in the batched path cannot hide behind
    /// every lane holding the same value.
    pub const DISTINCT_MESSAGES: [u128; AES_CALLS_PER_BATCH] = [
        u128::from_be(0x6bc1bee22e409f96e93d7e117393172a),
        u128::from_be(0xae2d8a571e03ac9c9eb76fac45af8e51),
        u128::from_be(0x30c81c46a35ce411e5fbc1191a0a52ef),
        u128::from_be(0xf69f2445df4f9b17ad2b417be66c3710),
        u128::from_be(0x00112233445566778899aabbccddeeff),
        u128::from_be(0x000102030405060708090a0b0c0d0e0f),
        u128::from_be(0xffffffffffffffffffffffffffffffff),
        u128::from_be(0x00000000000000000000000000000001),
    ];

    /// Splits a batch output into its [`AES_CALLS_PER_BATCH`] blocks.
    fn batch_blocks(batch: [u8; BYTES_PER_BATCH]) -> [u128; AES_CALLS_PER_BATCH] {
        core::array::from_fn(|i| {
            let block: [u8; BYTES_PER_AES_CALL] = batch
                [i * BYTES_PER_AES_CALL..(i + 1) * BYTES_PER_AES_CALL]
                .try_into()
                .expect("infallible");
            u128::from_ne_bytes(block)
        })
    }

    /// Feeds every block of `messages` through `generate_next`.
    fn encrypt_each<C: AesBlockCipher>(
        cipher: &mut C,
        messages: [u128; AES_CALLS_PER_BATCH],
    ) -> [u128; AES_CALLS_PER_BATCH] {
        messages.map(|m| u128::from_ne_bytes(cipher.generate_next(m)))
    }

    // ---------------------------------------------------------------------------------------
    // Key schedules. Round keys are a backend native vector type, so the caller passes a closure
    // that expands the key and normalizes the result to `u128`.
    // ---------------------------------------------------------------------------------------

    /// Checks the aes128 round keys against the FIPS 197 appendix A.1 schedule.
    pub fn test_key_schedule_128(expand: impl FnOnce(Aes128Key) -> [u128; AES_128_NUM_ROUND_KEYS]) {
        let actual = expand(Aes128Key::new(KEY_128));
        assert_eq!(actual, KEY_SCHEDULE_128);
    }

    /// Checks the aes256 round keys against the FIPS 197 appendix A.3 schedule.
    ///
    /// Pinning all 15 round keys also rules out the 256 path silently falling back to an aes128
    /// schedule, since the two disagree from round key 1 onwards.
    pub fn test_key_schedule_256(expand: impl FnOnce(Aes256Key) -> [u128; AES_256_NUM_ROUND_KEYS]) {
        let actual = expand(Aes256Key::new(KEY_256));
        assert_eq!(actual, KEY_SCHEDULE_256);
    }

    // ---------------------------------------------------------------------------------------
    // Encryption. These go through the `AesBlockCipher` trait, which means they also cover
    // whatever wrappers a backend puts between the trait methods and its inner routines.
    // ---------------------------------------------------------------------------------------

    /// FIPS 197 appendix C.1, single block through `generate_next`.
    pub fn test_fips197_c1_single_block<C: Aes128BlockCipher>() {
        let mut cipher = C::new(Aes128Key::new(KEY_128));
        assert_eq!(
            u128::from_ne_bytes(cipher.generate_next(PLAINTEXT)),
            CIPHERTEXT_128
        );
    }

    /// FIPS 197 appendix C.1, the same block in all lanes of `generate_batch`.
    pub fn test_fips197_c1_batch<C: Aes128BlockCipher>() {
        let mut cipher = C::new(Aes128Key::new(KEY_128));
        let blocks = batch_blocks(cipher.generate_batch([PLAINTEXT; AES_CALLS_PER_BATCH]));
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(*block, CIPHERTEXT_128, "lane {i}");
        }
    }

    /// FIPS 197 appendix C.3, single block through `generate_next`.
    pub fn test_fips197_c3_single_block<C: Aes256BlockCipher>() {
        let mut cipher = C::new(Aes256Key::new(KEY_256));
        assert_eq!(
            u128::from_ne_bytes(cipher.generate_next(PLAINTEXT)),
            CIPHERTEXT_256
        );
    }

    /// FIPS 197 appendix C.3, the same block in all lanes of `generate_batch`.
    pub fn test_fips197_c3_batch<C: Aes256BlockCipher>() {
        let mut cipher = C::new(Aes256Key::new(KEY_256));
        let blocks = batch_blocks(cipher.generate_batch([PLAINTEXT; AES_CALLS_PER_BATCH]));
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(*block, CIPHERTEXT_256, "lane {i}");
        }
    }

    /// NIST SP 800-38A ECB-AES256, four distinct blocks through `generate_next`.
    ///
    /// Uses a less structured key than the FIPS vector, so a byte ordering mistake in the key
    /// handling that the regular `00..1f` key happens to survive still shows up here.
    pub fn test_nist_ecb_aes256_single_blocks<C: Aes256BlockCipher>() {
        let mut cipher = C::new(Aes256Key::new(NIST_KEY_256));
        for (plaintext, expected) in NIST_BLOCKS_256 {
            assert_eq!(
                u128::from_ne_bytes(cipher.generate_next(plaintext)),
                expected
            );
        }
    }

    /// NIST SP 800-38A ECB-AES256 through `generate_batch`, the four blocks laid out twice so that
    /// neighbouring lanes always differ.
    pub fn test_nist_ecb_aes256_batch<C: Aes256BlockCipher>() {
        let mut cipher = C::new(Aes256Key::new(NIST_KEY_256));
        let data: [u128; AES_CALLS_PER_BATCH] =
            core::array::from_fn(|i| NIST_BLOCKS_256[i % NIST_BLOCKS_256.len()].0);

        let blocks = batch_blocks(cipher.generate_batch(data));

        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(
                *block,
                NIST_BLOCKS_256[i % NIST_BLOCKS_256.len()].1,
                "lane {i}"
            );
        }
    }

    /// `generate_batch` must agree with `generate_next` lane by lane on eight *different* blocks.
    ///
    /// The known answer vectors above cannot catch a lane mix-up on their own: where every lane
    /// holds the same value, any permutation of the lanes still passes.
    pub fn test_batch_matches_single_aes256<C: Aes256BlockCipher>() {
        let mut batched = C::new(Aes256Key::new(NIST_KEY_256));
        let mut single = C::new(Aes256Key::new(NIST_KEY_256));

        let from_batch = batch_blocks(batched.generate_batch(DISTINCT_MESSAGES));
        let from_single = encrypt_each(&mut single, DISTINCT_MESSAGES);

        for i in 0..AES_CALLS_PER_BATCH {
            assert_eq!(
                from_batch[i], from_single[i],
                "lane {i} of generate_batch disagrees with generate_next"
            );
        }
    }

    /// The aes256 cipher must not silently behave like the aes128 one.
    ///
    /// Both are keyed with the same leading 16 bytes, so an implementation that ignored the second
    /// half of the 256 bit key, or that ran 10 rounds instead of 14, would agree here.
    pub fn test_aes128_and_aes256_differ<C128, C256>()
    where
        C128: Aes128BlockCipher,
        C256: Aes256BlockCipher,
    {
        let leading_16_bytes: [u8; BYTES_PER_AES_CALL] = KEY_256[..BYTES_PER_AES_CALL]
            .try_into()
            .expect("infallible");

        let mut cipher_128 = C128::new(Aes128Key::new(u128::from_ne_bytes(leading_16_bytes)));
        let mut cipher_256 = C256::new(Aes256Key::new(KEY_256));

        assert_ne!(
            cipher_128.generate_next(PLAINTEXT),
            cipher_256.generate_next(PLAINTEXT)
        );
    }
}
