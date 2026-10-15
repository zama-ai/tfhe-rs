//! fhevm GPU operator support matrix
//!
//! Type sets:
//! - `A = {U8, U16, U32, U64, U128}` — arithmetic types exposed by the executor
//! - `N = A ∪ {U256}` — all exposed unsigned integer types
//! - `H = {B} ∪ N ∪ {U160}` — all eight exposed value types
//! - `B = {Bool}`
//! - `U160 = eaddress`
//!
//! For every binary opcode: position 0 is always encrypted; position 1 is encrypted with
//! **exactly the same type** (`scalarByte=0x00`) or a clear scalar of that type
//! (`scalarByte=0x01`). Mixed encrypted widths are never sent to the backend; the Solidity
//! library inserts casts before dispatch.
//!
//! | Opcode | Operation       | Pos 0          | Pos 1                    | Output  | Enc-enc | Enc-scalar |
//! |--------|-----------------|----------------|--------------------------|---------|---------|------------|
//! | 0      | fheAdd          | E(T), T ∈ A    | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 1      | fheSub          | E(T), T ∈ A    | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 2      | fheMul          | E(T), T ∈ A    | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 3      | fheDiv          | E(T), T ∈ A    | S(T), nonzero            | E(T)    | —       | yes        |
//! | 4      | fheRem          | E(T), T ∈ A    | S(T), nonzero            | E(T)    | —       | yes        |
//! | 5      | fheBitAnd       | E(T), T ∈ B∪N  | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 6      | fheBitOr        | E(T), T ∈ B∪N  | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 7      | fheBitXor       | E(T), T ∈ B∪N  | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 8      | fheShl          | E(T), T ∈ N    | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 9      | fheShr          | E(T), T ∈ N    | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 10     | fheRotl         | E(T), T ∈ N    | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 11     | fheRotr         | E(T), T ∈ N    | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 12     | fheEq           | E(T), T ∈ H    | E(T) or S(T)             | E(B)    | yes     | yes        |
//! | 13     | fheNe           | E(T), T ∈ H    | E(T) or S(T)             | E(B)    | yes     | yes        |
//! | 14     | fheGe           | E(T), T ∈ A    | E(T) or S(T)             | E(B)    | yes     | yes        |
//! | 15     | fheGt           | E(T), T ∈ A    | E(T) or S(T)             | E(B)    | yes     | yes        |
//! | 16     | fheLe           | E(T), T ∈ A    | E(T) or S(T)             | E(B)    | yes     | yes        |
//! | 17     | fheLt           | E(T), T ∈ A    | E(T) or S(T)             | E(B)    | yes     | yes        |
//! | 18     | fheMin          | E(T), T ∈ A    | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 19     | fheMax          | E(T), T ∈ A    | E(T) or S(T)             | E(T)    | yes     | yes        |
//! | 20     | fheNeg          | E(T), T ∈ N    | —                        | E(T)    | unary   | —          |
//! | 21     | fheNot          | E(T), T ∈ B∪N  | —                        | E(T)    | unary   | —          |
//! | 23     | cast            | E(T), T ∈ B∪N  | clear dest type D ∈ N    | E(D)    | unary   | —          |
//! | 24     | trivialEncrypt  | clear S(T)     | clear type ID T ∈ H      | E(T)    | —       | source     |
//! | 25     | fheIfThenElse   | E(B) control   | E(T) true, T ∈ H         | E(T)    | all-enc | —          |
//! | 26     | fheRand         | clear seed     | clear type ID T ∈ B∪N   | E(T)    | —       | generated  |
//! | 27     | fheRandBounded  | clear seed     | clear bound; T ∈ N       | E(T)    | —       | generated  |
//! | 28     | fheSum          | E(T)…, T ∈ A   | (variadic, same T)        | E(T)    | variadic| —          |
//! | 29     | fheIsIn         | E(T) + set…    | T ∈ N∪{U160}             | E(B)    | variadic| —          |
//! | 30     | fheMulDiv       | E(T), T∈{U8..U64}| E(T) or S(T) × S(T) div| E(T)    | yes     | yes        |
//!
//! Additional constraints:
//! - fheDiv / fheRem: scalar divisor is always nonzero.
//! - fheIfThenElse: all three operands are encrypted; no scalar branch variant at executor level.
//! - fheSum: n=0 is valid (produces encrypted zero); max n is 100 for U8/U16/U32, 60 for U64/U128.
//! - fheIsIn: empty set is valid (produces encrypted false); max set size follows fheSum limits,
//!   plus 60 for U160/U256.
//! - fheRandBounded: bound must be a positive power of two; for U256 max accepted power is 2^255.
//! - U160 (eaddress): only opcodes 12, 13, 24, 25, 29 are valid. No arithmetic, shifts, bitwise,
//!   neg, cast, or random.
//! - U256: opcodes 5–11, 12–13, 20–21, 23, 24, 25, 26, 27, 29 only. No add/sub/mul/div/rem, ordered
//!   comparisons, min/max, sum, or MulDiv.
//! - fheMulDiv (opcode 30): T ∈ {U8, U16, U32, U64} only. U128 and U256 are excluded.

#![cfg(feature = "gpu")]

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::gpu::get_number_of_gpus;
use crate::high_level_api::prelude::*;
use crate::integer::server_key::radix_parallel::tests_unsigned::panic_if_any_block_is_not_clean_or_trivial;
use crate::integer::U256;
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::{
    set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, CudaGpuChoice,
    CustomMultiGpuIndexes, FheBool, FheUint128, FheUint16, FheUint160, FheUint256, FheUint32,
    FheUint64, FheUint8, GpuIndex, Seed,
};
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::Seeder;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

fn seeded_shuffle(v: &mut [u32], datagen: &mut DeterministicSeeder<DefaultRandomGenerator>) {
    for i in (1..v.len()).rev() {
        let j = datagen.seed().0 as usize % (i + 1);
        v.swap(i, j);
    }
}

fn make_random_gpu_set(datagen: &mut DeterministicSeeder<DefaultRandomGenerator>) -> CudaGpuChoice {
    #[cfg(not(feature = "gpu-debug-fake-multi-gpu"))]
    let num_gpus = get_number_of_gpus();

    #[cfg(feature = "gpu-debug-fake-multi-gpu")]
    let num_gpus_to_use = 2usize;

    #[cfg(not(feature = "gpu-debug-fake-multi-gpu"))]
    let num_gpus_to_use = if num_gpus > 1 {
        (1 + datagen.seed().0 as u32 % (num_gpus - 1)) as usize
    } else {
        1usize
    };

    #[cfg(feature = "gpu-debug-fake-multi-gpu")]
    let mut all_gpu_indexes: Vec<u32> = vec![0; num_gpus_to_use];

    #[cfg(not(feature = "gpu-debug-fake-multi-gpu"))]
    let mut all_gpu_indexes: Vec<u32> = (0..num_gpus).collect();

    seeded_shuffle(&mut all_gpu_indexes, datagen);

    let gpu_indexes_to_use = &all_gpu_indexes[..num_gpus_to_use];
    let gpu_indexes = CustomMultiGpuIndexes::new(
        gpu_indexes_to_use
            .iter()
            .map(|idx| GpuIndex::new(*idx))
            .collect(),
    );
    println!("Setting up server key on GPUs: [{gpu_indexes_to_use:?}]");
    gpu_indexes.into()
}

pub(crate) fn setup_gpu_random() -> ClientKey {
    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .use_dedicated_oprf_key(true)
            .build();

    let client_key = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&client_key);

    let seed = Seed(rand::random::<u128>());
    let mut datagen = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
    let gpu_choice = make_random_gpu_set(&mut datagen);
    let server_key = compressed_sks.decompress_to_specific_gpu(gpu_choice);
    set_server_key(server_key);

    client_key
}

pub(crate) const GPU_SETUP_FN: [fn() -> ClientKey; 1] = [setup_gpu_random];

// ---------------------------------------------------------------------------
// Extreme test vectors
// ---------------------------------------------------------------------------

const EXTREME_BOOL: [bool; 2] = [false, true];
const EXTREME_U8: [u8; 9] = [0, 1, 2, 85, 127, 128, 170, 254, 255];
const EXTREME_U16: [u16; 9] = [0, 1, 2, 0x5555, 0x7FFF, 0x8000, 0xAAAA, 0xFFFE, 0xFFFF];
const EXTREME_U32: [u32; 9] = [
    0,
    1,
    2,
    0x5555_5555,
    0x7FFF_FFFF,
    0x8000_0000,
    0xAAAA_AAAA,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
];
const EXTREME_U64: [u64; 9] = [
    0,
    1,
    2,
    0x5555_5555_5555_5555,
    0x7FFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000,
    0xAAAA_AAAA_AAAA_AAAA,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];
const EXTREME_U128: [u128; 9] = [
    0,
    1,
    2,
    0x5555_5555_5555_5555_5555_5555_5555_5555,
    0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000_0000_0000_0000_0000,
    0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA,
    0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
];

fn extreme_u256() -> Vec<U256> {
    vec![
        U256::ZERO,
        U256::ONE,
        U256::from(2u64),
        U256::from((
            0x5555_5555_5555_5555_5555_5555_5555_5555u128,
            0x5555_5555_5555_5555_5555_5555_5555_5555u128,
        )),
        U256::from((
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128,
            0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128,
        )),
        U256::from((0u128, 0x8000_0000_0000_0000_0000_0000_0000_0000u128)),
        U256::from((
            0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128,
            0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128,
        )),
        U256::from((
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFEu128,
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128,
        )),
        U256::MAX,
    ]
}

// u160 values stored as U256 (upper 96 bits zero)
fn extreme_u160() -> Vec<U256> {
    let mask160 = (U256::ONE << 160u32) - U256::ONE;
    vec![
        U256::ZERO,
        U256::ONE,
        U256::from(2u64),
        U256::from((0x5555_5555_5555_5555_5555_5555_5555_5555u128, 0u128)) & mask160,
        U256::from((0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128, 0u128)) & mask160,
        U256::from((0x8000_0000_0000_0000_0000_0000_0000_0000u128, 0u128)) & mask160,
        U256::from((0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128, 0u128)) & mask160,
        (U256::ONE << 160u32) - U256::from(2u64),
        (U256::ONE << 160u32) - U256::ONE,
    ]
}

// ---------------------------------------------------------------------------
// Divisor test vectors
// ---------------------------------------------------------------------------

const DIVISORS_U8: [u8; 9] = [1, 2, 4, 128, 6, 170, 85, 127, 255];
const DIVISORS_U16: [u16; 9] = [1, 2, 4, 256, 32768, 6, 0xAAAA, 0x5555, 0xFFFF];
const DIVISORS_U32: [u32; 9] = [
    1,
    2,
    4,
    0x8000_0000,
    65536,
    6,
    0xAAAA_AAAA,
    0x5555_5555,
    0xFFFF_FFFF,
];
const DIVISORS_U64: [u64; 9] = [
    1,
    2,
    4,
    0x8000_0000_0000_0000,
    65536,
    6,
    0xAAAA_AAAA_AAAA_AAAA,
    0x5555_5555_5555_5555,
    0xFFFF_FFFF_FFFF_FFFF,
];
const DIVISORS_U128: [u128; 9] = [
    1,
    2,
    4,
    0x8000_0000_0000_0000_0000_0000_0000_0000,
    65536,
    6,
    0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA,
    0x5555_5555_5555_5555_5555_5555_5555_5555,
    0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
];

// ---------------------------------------------------------------------------
// Helper: check ciphertext noise before decrypting
// ---------------------------------------------------------------------------

fn check_uint_noise(ct: &FheUint8, cks: &ClientKey) {
    panic_if_any_block_is_not_clean_or_trivial(&ct.ciphertext.clone().into_cpu(), cks);
}
fn check_uint16_noise(ct: &FheUint16, cks: &ClientKey) {
    panic_if_any_block_is_not_clean_or_trivial(&ct.ciphertext.clone().into_cpu(), cks);
}
fn check_uint32_noise(ct: &FheUint32, cks: &ClientKey) {
    panic_if_any_block_is_not_clean_or_trivial(&ct.ciphertext.clone().into_cpu(), cks);
}
fn check_uint64_noise(ct: &FheUint64, cks: &ClientKey) {
    panic_if_any_block_is_not_clean_or_trivial(&ct.ciphertext.clone().into_cpu(), cks);
}
fn check_uint128_noise(ct: &FheUint128, cks: &ClientKey) {
    panic_if_any_block_is_not_clean_or_trivial(&ct.ciphertext.clone().into_cpu(), cks);
}
fn check_uint256_noise(ct: &FheUint256, cks: &ClientKey) {
    panic_if_any_block_is_not_clean_or_trivial(&ct.ciphertext.clone().into_cpu(), cks);
}
fn check_uint160_noise(ct: &FheUint160, cks: &ClientKey) {
    panic_if_any_block_is_not_clean_or_trivial(&ct.ciphertext.clone().into_cpu(), cks);
}

// ---------------------------------------------------------------------------
// OPCODE 0: fheAdd  (T ∈ {u8,u16,u32,u64,u128})
// ---------------------------------------------------------------------------

fn test_case_fhevm_add_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let result = &enc_a + &enc_b;
            check_uint_noise(&result, cks);
            let dec: u8 = result.decrypt(cks);
            assert_eq!(dec, a.wrapping_add(b), "add_u8 enc+enc {a}+{b}");
            let result2 = &enc_a + b;
            check_uint_noise(&result2, cks);
            let dec2: u8 = result2.decrypt(cks);
            assert_eq!(dec2, a.wrapping_add(b), "add_u8 enc+scalar {a}+{b}");
        }
    }
}

fn test_case_fhevm_add_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let result = &enc_a + &enc_b;
            check_uint16_noise(&result, cks);
            let dec: u16 = result.decrypt(cks);
            assert_eq!(dec, a.wrapping_add(b), "add_u16 {a}+{b}");
            let result2 = &enc_a + b;
            check_uint16_noise(&result2, cks);
            let dec2: u16 = result2.decrypt(cks);
            assert_eq!(dec2, a.wrapping_add(b));
        }
    }
}

fn test_case_fhevm_add_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = &enc_a + &enc_b;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_add(b), "add_u32 {a}+{b}");
            let r2 = &enc_a + b;
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_add(b));
        }
    }
}

fn test_case_fhevm_add_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = &enc_a + &enc_b;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_add(b), "add_u64 {a}+{b}");
            let r2 = &enc_a + b;
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_add(b));
        }
    }
}

fn test_case_fhevm_add_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = &enc_a + &enc_b;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_add(b), "add_u128 {a}+{b}");
            let r2 = &enc_a + b;
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_add(b));
        }
    }
}

#[test]
fn test_fhevm_gpu_add_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_add_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_add_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_add_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_add_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_add_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_add_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_add_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_add_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_add_u128(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 1: fheSub
// ---------------------------------------------------------------------------

fn test_case_fhevm_sub_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = &enc_a - &enc_b;
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_sub(b), "sub_u8 {a}-{b}");
            let r2 = &enc_a - b;
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_sub(b));
        }
    }
}

fn test_case_fhevm_sub_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = &enc_a - &enc_b;
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_sub(b));
            let r2 = &enc_a - b;
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_sub(b));
        }
    }
}

fn test_case_fhevm_sub_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = &enc_a - &enc_b;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_sub(b));
            let r2 = &enc_a - b;
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_sub(b));
        }
    }
}

fn test_case_fhevm_sub_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = &enc_a - &enc_b;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_sub(b));
            let r2 = &enc_a - b;
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_sub(b));
        }
    }
}

fn test_case_fhevm_sub_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = &enc_a - &enc_b;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_sub(b));
            let r2 = &enc_a - b;
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_sub(b));
        }
    }
}

#[test]
fn test_fhevm_gpu_sub_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sub_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_sub_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sub_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_sub_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sub_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_sub_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sub_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_sub_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sub_u128(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 2: fheMul
// ---------------------------------------------------------------------------

fn test_case_fhevm_mul_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = &enc_a * &enc_b;
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_mul(b), "mul_u8 {a}*{b}");
            let r2 = &enc_a * b;
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_mul(b));
        }
    }
}

fn test_case_fhevm_mul_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = &enc_a * &enc_b;
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_mul(b));
            let r2 = &enc_a * b;
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_mul(b));
        }
    }
}

fn test_case_fhevm_mul_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = &enc_a * &enc_b;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_mul(b));
            let r2 = &enc_a * b;
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_mul(b));
        }
    }
}

fn test_case_fhevm_mul_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = &enc_a * &enc_b;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_mul(b));
            let r2 = &enc_a * b;
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_mul(b));
        }
    }
}

fn test_case_fhevm_mul_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = &enc_a * &enc_b;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_mul(b));
            let r2 = &enc_a * b;
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_mul(b));
        }
    }
}

#[test]
fn test_fhevm_gpu_mul_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_mul_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_mul_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_mul_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_mul_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_mul_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_mul_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_mul_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_mul_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_mul_u128(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 3: fheDiv (scalar-only)
// ---------------------------------------------------------------------------

fn test_case_fhevm_div_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &DIVISORS_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let r = &enc_a / b;
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a / b, "div_u8 {a}/{b}");
        }
    }
}

fn test_case_fhevm_div_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &DIVISORS_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let r = &enc_a / b;
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a / b, "div_u16 {a}/{b}");
        }
    }
}

fn test_case_fhevm_div_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &DIVISORS_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let r = &enc_a / b;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a / b, "div_u32 {a}/{b}");
        }
    }
}

fn test_case_fhevm_div_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &DIVISORS_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let r = &enc_a / b;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a / b, "div_u64 {a}/{b}");
        }
    }
}

fn test_case_fhevm_div_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &DIVISORS_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let r = &enc_a / b;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a / b, "div_u128 {a}/{b}");
        }
    }
}

#[test]
fn test_fhevm_gpu_div_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_div_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_div_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_div_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_div_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_div_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_div_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_div_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_div_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_div_u128(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 4: fheRem (scalar-only)
// ---------------------------------------------------------------------------

fn test_case_fhevm_rem_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &DIVISORS_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let r = &enc_a % b;
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a % b, "rem_u8 {a}%{b}");
        }
    }
}

fn test_case_fhevm_rem_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &DIVISORS_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let r = &enc_a % b;
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a % b);
        }
    }
}

fn test_case_fhevm_rem_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &DIVISORS_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let r = &enc_a % b;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a % b);
        }
    }
}

fn test_case_fhevm_rem_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &DIVISORS_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let r = &enc_a % b;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a % b);
        }
    }
}

fn test_case_fhevm_rem_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &DIVISORS_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let r = &enc_a % b;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a % b);
        }
    }
}

#[test]
fn test_fhevm_gpu_rem_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rem_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rem_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rem_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rem_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rem_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rem_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rem_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rem_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rem_u128(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 5: fheBitAnd  T ∈ {bool, u8..u256}
// ---------------------------------------------------------------------------

fn test_case_fhevm_bitand_bool(cks: &ClientKey) {
    for &a in &EXTREME_BOOL {
        for &b in &EXTREME_BOOL {
            let enc_a = FheBool::encrypt(a, cks);
            let enc_b = FheBool::encrypt(b, cks);
            let r = &enc_a & &enc_b;
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a & b, "bitand_bool {a}&{b}");
            let r2 = &enc_a & b;
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a & b);
        }
    }
}

fn test_case_fhevm_bitand_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = &enc_a & &enc_b;
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a & b);
            let r2 = &enc_a & b;
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, a & b);
        }
    }
}

fn test_case_fhevm_bitand_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = &enc_a & &enc_b;
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a & b);
            let r2 = &enc_a & b;
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, a & b);
        }
    }
}

fn test_case_fhevm_bitand_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = &enc_a & &enc_b;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a & b);
            let r2 = &enc_a & b;
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a & b);
        }
    }
}

fn test_case_fhevm_bitand_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = &enc_a & &enc_b;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a & b);
            let r2 = &enc_a & b;
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a & b);
        }
    }
}

fn test_case_fhevm_bitand_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = &enc_a & &enc_b;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a & b);
            let r2 = &enc_a & b;
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a & b);
        }
    }
}

fn test_case_fhevm_bitand_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        for b in extreme_u256() {
            let enc_a = FheUint256::encrypt(a, cks);
            let enc_b = FheUint256::encrypt(b, cks);
            let r = &enc_a & &enc_b;
            check_uint256_noise(&r, cks);
            let d: U256 = r.decrypt(cks);
            assert_eq!(d, a & b);
            let r2 = &enc_a & b;
            check_uint256_noise(&r2, cks);
            let d2: U256 = r2.decrypt(cks);
            assert_eq!(d2, a & b);
        }
    }
}

#[test]
fn test_fhevm_gpu_bitand_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitand_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitand_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitand_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitand_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitand_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitand_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitand_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitand_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitand_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitand_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitand_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitand_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitand_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 6: fheBitOr
// ---------------------------------------------------------------------------

fn test_case_fhevm_bitor_bool(cks: &ClientKey) {
    for &a in &EXTREME_BOOL {
        for &b in &EXTREME_BOOL {
            let enc_a = FheBool::encrypt(a, cks);
            let enc_b = FheBool::encrypt(b, cks);
            let r = &enc_a | &enc_b;
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a | b);
            let r2 = &enc_a | b;
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a | b);
        }
    }
}
fn test_case_fhevm_bitor_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = &enc_a | &enc_b;
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a | b);
            let r2 = &enc_a | b;
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, a | b);
        }
    }
}
fn test_case_fhevm_bitor_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = &enc_a | &enc_b;
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a | b);
            let r2 = &enc_a | b;
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, a | b);
        }
    }
}
fn test_case_fhevm_bitor_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = &enc_a | &enc_b;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a | b);
            let r2 = &enc_a | b;
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a | b);
        }
    }
}
fn test_case_fhevm_bitor_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = &enc_a | &enc_b;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a | b);
            let r2 = &enc_a | b;
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a | b);
        }
    }
}
fn test_case_fhevm_bitor_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = &enc_a | &enc_b;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a | b);
            let r2 = &enc_a | b;
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a | b);
        }
    }
}
fn test_case_fhevm_bitor_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        for b in extreme_u256() {
            let enc_a = FheUint256::encrypt(a, cks);
            let enc_b = FheUint256::encrypt(b, cks);
            let r = &enc_a | &enc_b;
            check_uint256_noise(&r, cks);
            let d: U256 = r.decrypt(cks);
            assert_eq!(d, a | b);
            let r2 = &enc_a | b;
            check_uint256_noise(&r2, cks);
            let d2: U256 = r2.decrypt(cks);
            assert_eq!(d2, a | b);
        }
    }
}

#[test]
fn test_fhevm_gpu_bitor_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitor_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitor_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitor_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitor_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitor_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitor_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitor_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitor_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitor_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitor_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitor_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitor_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitor_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 7: fheBitXor
// ---------------------------------------------------------------------------

fn test_case_fhevm_bitxor_bool(cks: &ClientKey) {
    for &a in &EXTREME_BOOL {
        for &b in &EXTREME_BOOL {
            let enc_a = FheBool::encrypt(a, cks);
            let enc_b = FheBool::encrypt(b, cks);
            let r = &enc_a ^ &enc_b;
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a ^ b);
            let r2 = &enc_a ^ b;
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a ^ b);
        }
    }
}
fn test_case_fhevm_bitxor_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = &enc_a ^ &enc_b;
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a ^ b);
            let r2 = &enc_a ^ b;
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, a ^ b);
        }
    }
}
fn test_case_fhevm_bitxor_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = &enc_a ^ &enc_b;
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a ^ b);
            let r2 = &enc_a ^ b;
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, a ^ b);
        }
    }
}
fn test_case_fhevm_bitxor_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = &enc_a ^ &enc_b;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a ^ b);
            let r2 = &enc_a ^ b;
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a ^ b);
        }
    }
}
fn test_case_fhevm_bitxor_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = &enc_a ^ &enc_b;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a ^ b);
            let r2 = &enc_a ^ b;
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a ^ b);
        }
    }
}
fn test_case_fhevm_bitxor_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = &enc_a ^ &enc_b;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a ^ b);
            let r2 = &enc_a ^ b;
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a ^ b);
        }
    }
}
fn test_case_fhevm_bitxor_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        for b in extreme_u256() {
            let enc_a = FheUint256::encrypt(a, cks);
            let enc_b = FheUint256::encrypt(b, cks);
            let r = &enc_a ^ &enc_b;
            check_uint256_noise(&r, cks);
            let d: U256 = r.decrypt(cks);
            assert_eq!(d, a ^ b);
            let r2 = &enc_a ^ b;
            check_uint256_noise(&r2, cks);
            let d2: U256 = r2.decrypt(cks);
            assert_eq!(d2, a ^ b);
        }
    }
}

#[test]
fn test_fhevm_gpu_bitxor_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitxor_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitxor_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitxor_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitxor_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitxor_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitxor_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitxor_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitxor_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitxor_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitxor_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitxor_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_bitxor_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_bitxor_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// Shift/rotate helpers
// ---------------------------------------------------------------------------

fn shift_amounts_u8() -> Vec<u8> {
    vec![0, 1, 3, 4, 5, 7, 8, 9, 15, 255]
}
fn shift_amounts_u16() -> Vec<u16> {
    vec![0, 1, 7, 8, 9, 15, 16, 17, 31, 255]
}
fn shift_amounts_u32() -> Vec<u32> {
    vec![0, 1, 15, 16, 17, 31, 32, 33, 63, 255]
}
fn shift_amounts_u64() -> Vec<u64> {
    vec![0, 1, 31, 32, 33, 63, 64, 65, 127, 255]
}
fn shift_amounts_u128() -> Vec<u128> {
    vec![0, 1, 63, 64, 65, 127, 128, 129, 255, 255]
}
fn shift_amounts_u256() -> Vec<U256> {
    vec![
        U256::ZERO,
        U256::ONE,
        U256::from(127u64),
        U256::from(128u64),
        U256::from(129u64),
        U256::from(255u64),
        U256::from(256u64),
        U256::from(257u64),
        U256::from(511u64),
        U256::from(255u64),
    ]
}

// ---------------------------------------------------------------------------
// OPCODE 8: fheShl
// ---------------------------------------------------------------------------

fn test_case_fhevm_shl_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &s in &shift_amounts_u8() {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_s = FheUint8::encrypt(s, cks);
            let r = &enc_a << &enc_s;
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shl((s % 8) as u32));
            let r2 = &enc_a << s;
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shl((s % 8) as u32));
        }
    }
}
fn test_case_fhevm_shl_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &s in &shift_amounts_u16() {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_s = FheUint16::encrypt(s, cks);
            let r = &enc_a << &enc_s;
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shl((s % 16) as u32));
            let r2 = &enc_a << s;
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shl((s % 16) as u32));
        }
    }
}
fn test_case_fhevm_shl_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &s in &shift_amounts_u32() {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_s = FheUint32::encrypt(s, cks);
            let r = &enc_a << &enc_s;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shl(s % 32));
            let r2 = &enc_a << s;
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shl(s % 32));
        }
    }
}
fn test_case_fhevm_shl_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &s in &shift_amounts_u64() {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_s = FheUint64::encrypt(s, cks);
            let r = &enc_a << &enc_s;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shl((s % 64) as u32));
            let r2 = &enc_a << s;
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shl((s % 64) as u32));
        }
    }
}
fn test_case_fhevm_shl_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &s in &shift_amounts_u128() {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_s = FheUint128::encrypt(s, cks);
            let r = &enc_a << &enc_s;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shl((s % 128) as u32));
            let r2 = &enc_a << s;
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shl((s % 128) as u32));
        }
    }
}
fn test_case_fhevm_shl_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        for s in shift_amounts_u256() {
            let enc_a = FheUint256::encrypt(a, cks);
            let enc_s = FheUint256::encrypt(s, cks);
            let r = &enc_a << &enc_s;
            check_uint256_noise(&r, cks);
            let sh = (s % U256::from(256u64)).0[0] as u32;
            let expected = a << sh;
            let d: U256 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = &enc_a << s;
            check_uint256_noise(&r2, cks);
            let d2: U256 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}

#[test]
fn test_fhevm_gpu_shl_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shl_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shl_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shl_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shl_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shl_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shl_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shl_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shl_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shl_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shl_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shl_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 9: fheShr
// ---------------------------------------------------------------------------

fn test_case_fhevm_shr_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &s in &shift_amounts_u8() {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_s = FheUint8::encrypt(s, cks);
            let r = &enc_a >> &enc_s;
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shr((s % 8) as u32));
            let r2 = &enc_a >> s;
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shr((s % 8) as u32));
        }
    }
}
fn test_case_fhevm_shr_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &s in &shift_amounts_u16() {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_s = FheUint16::encrypt(s, cks);
            let r = &enc_a >> &enc_s;
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shr((s % 16) as u32));
            let r2 = &enc_a >> s;
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shr((s % 16) as u32));
        }
    }
}
fn test_case_fhevm_shr_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &s in &shift_amounts_u32() {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_s = FheUint32::encrypt(s, cks);
            let r = &enc_a >> &enc_s;
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shr(s % 32));
            let r2 = &enc_a >> s;
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shr(s % 32));
        }
    }
}
fn test_case_fhevm_shr_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &s in &shift_amounts_u64() {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_s = FheUint64::encrypt(s, cks);
            let r = &enc_a >> &enc_s;
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shr((s % 64) as u32));
            let r2 = &enc_a >> s;
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shr((s % 64) as u32));
        }
    }
}
fn test_case_fhevm_shr_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &s in &shift_amounts_u128() {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_s = FheUint128::encrypt(s, cks);
            let r = &enc_a >> &enc_s;
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a.wrapping_shr((s % 128) as u32));
            let r2 = &enc_a >> s;
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a.wrapping_shr((s % 128) as u32));
        }
    }
}
fn test_case_fhevm_shr_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        for s in shift_amounts_u256() {
            let enc_a = FheUint256::encrypt(a, cks);
            let enc_s = FheUint256::encrypt(s, cks);
            let r = &enc_a >> &enc_s;
            check_uint256_noise(&r, cks);
            let sh = (s % U256::from(256u64)).0[0] as u32;
            let expected = a >> sh;
            let d: U256 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = &enc_a >> s;
            check_uint256_noise(&r2, cks);
            let d2: U256 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}

#[test]
fn test_fhevm_gpu_shr_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shr_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shr_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shr_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shr_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shr_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shr_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shr_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shr_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shr_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_shr_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_shr_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 10: fheRotl
// ---------------------------------------------------------------------------

fn test_case_fhevm_rotl_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &s in &shift_amounts_u8() {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_s = FheUint8::encrypt(s, cks);
            let r = (&enc_a).rotate_left(&enc_s);
            check_uint_noise(&r, cks);
            let sh = (s % 8) as u32;
            let expected = a.rotate_left(sh);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_left(s);
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotl_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &s in &shift_amounts_u16() {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_s = FheUint16::encrypt(s, cks);
            let r = (&enc_a).rotate_left(&enc_s);
            check_uint16_noise(&r, cks);
            let sh = (s % 16) as u32;
            let expected = a.rotate_left(sh);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_left(s);
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotl_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &s in &shift_amounts_u32() {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_s = FheUint32::encrypt(s, cks);
            let r = (&enc_a).rotate_left(&enc_s);
            check_uint32_noise(&r, cks);
            let sh = s % 32;
            let expected = a.rotate_left(sh);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_left(s);
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotl_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &s in &shift_amounts_u64() {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_s = FheUint64::encrypt(s, cks);
            let r = (&enc_a).rotate_left(&enc_s);
            check_uint64_noise(&r, cks);
            let sh = (s % 64) as u32;
            let expected = a.rotate_left(sh);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_left(s);
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotl_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &s in &shift_amounts_u128() {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_s = FheUint128::encrypt(s, cks);
            let r = (&enc_a).rotate_left(&enc_s);
            check_uint128_noise(&r, cks);
            let sh = (s % 128) as u32;
            let expected = a.rotate_left(sh);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_left(s);
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotl_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        for s in shift_amounts_u256() {
            let enc_a = FheUint256::encrypt(a, cks);
            let enc_s = FheUint256::encrypt(s, cks);
            let r = (&enc_a).rotate_left(&enc_s);
            check_uint256_noise(&r, cks);
            let sh = (s % U256::from(256u64)).0[0] as u32;
            let expected = (a << sh) | (a >> (256u32.wrapping_sub(sh)));
            let d: U256 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_left(s);
            check_uint256_noise(&r2, cks);
            let d2: U256 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}

#[test]
fn test_fhevm_gpu_rotl_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotl_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotl_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotl_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotl_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotl_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotl_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotl_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotl_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotl_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotl_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotl_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 11: fheRotr
// ---------------------------------------------------------------------------

fn test_case_fhevm_rotr_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &s in &shift_amounts_u8() {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_s = FheUint8::encrypt(s, cks);
            let r = (&enc_a).rotate_right(&enc_s);
            check_uint_noise(&r, cks);
            let sh = (s % 8) as u32;
            let expected = a.rotate_right(sh);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_right(s);
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotr_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &s in &shift_amounts_u16() {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_s = FheUint16::encrypt(s, cks);
            let r = (&enc_a).rotate_right(&enc_s);
            check_uint16_noise(&r, cks);
            let sh = (s % 16) as u32;
            let expected = a.rotate_right(sh);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_right(s);
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotr_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &s in &shift_amounts_u32() {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_s = FheUint32::encrypt(s, cks);
            let r = (&enc_a).rotate_right(&enc_s);
            check_uint32_noise(&r, cks);
            let sh = s % 32;
            let expected = a.rotate_right(sh);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_right(s);
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotr_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &s in &shift_amounts_u64() {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_s = FheUint64::encrypt(s, cks);
            let r = (&enc_a).rotate_right(&enc_s);
            check_uint64_noise(&r, cks);
            let sh = (s % 64) as u32;
            let expected = a.rotate_right(sh);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_right(s);
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotr_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &s in &shift_amounts_u128() {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_s = FheUint128::encrypt(s, cks);
            let r = (&enc_a).rotate_right(&enc_s);
            check_uint128_noise(&r, cks);
            let sh = (s % 128) as u32;
            let expected = a.rotate_right(sh);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_right(s);
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}
fn test_case_fhevm_rotr_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        for s in shift_amounts_u256() {
            let enc_a = FheUint256::encrypt(a, cks);
            let enc_s = FheUint256::encrypt(s, cks);
            let r = (&enc_a).rotate_right(&enc_s);
            check_uint256_noise(&r, cks);
            let sh = (s % U256::from(256u64)).0[0] as u32;
            let expected = (a >> sh) | (a << (256u32.wrapping_sub(sh)));
            let d: U256 = r.decrypt(cks);
            assert_eq!(d, expected);
            let r2 = (&enc_a).rotate_right(s);
            check_uint256_noise(&r2, cks);
            let d2: U256 = r2.decrypt(cks);
            assert_eq!(d2, expected);
        }
    }
}

#[test]
fn test_fhevm_gpu_rotr_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotr_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotr_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotr_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotr_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotr_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotr_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotr_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotr_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotr_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rotr_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rotr_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODES 12-19: Comparison ops (eq, ne, ge, gt, le, lt, min, max)
// T ∈ H for eq/ne (bool + u8..u256 + u160), T ∈ A for ge/gt/le/lt/min/max
// ---------------------------------------------------------------------------

// --- fheEq ---
fn test_case_fhevm_eq_bool(cks: &ClientKey) {
    for &a in &EXTREME_BOOL {
        for &b in &EXTREME_BOOL {
            let enc_a = FheBool::encrypt(a, cks);
            let enc_b = FheBool::encrypt(b, cks);
            let r = enc_a.eq(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a == b);
            let r2 = enc_a.eq(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a == b);
        }
    }
}
fn test_case_fhevm_eq_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = enc_a.eq(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a == b);
            let r2 = enc_a.eq(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a == b);
        }
    }
}
fn test_case_fhevm_eq_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = enc_a.eq(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a == b);
            let r2 = enc_a.eq(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a == b);
        }
    }
}
fn test_case_fhevm_eq_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = enc_a.eq(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a == b);
            let r2 = enc_a.eq(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a == b);
        }
    }
}
fn test_case_fhevm_eq_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = enc_a.eq(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a == b);
            let r2 = enc_a.eq(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a == b);
        }
    }
}
fn test_case_fhevm_eq_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = enc_a.eq(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a == b);
            let r2 = enc_a.eq(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a == b);
        }
    }
}
fn test_case_fhevm_eq_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        for b in extreme_u256() {
            let enc_a = FheUint256::encrypt(a, cks);
            let enc_b = FheUint256::encrypt(b, cks);
            let r = enc_a.eq(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a == b);
            let r2 = enc_a.eq(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a == b);
        }
    }
}
fn test_case_fhevm_eq_u160(cks: &ClientKey) {
    for a in extreme_u160() {
        for b in extreme_u160() {
            let enc_a = FheUint160::encrypt(a, cks);
            let enc_b = FheUint160::encrypt(b, cks);
            let r = enc_a.eq(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a == b);
            let r2 = enc_a.eq(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a == b);
        }
    }
}

#[test]
fn test_fhevm_gpu_eq_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_eq_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_eq_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_eq_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_eq_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_eq_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_eq_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_eq_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_eq_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_eq_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_eq_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_eq_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_eq_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_eq_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_eq_u160() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_eq_u160(&cks);
    }
}

// --- fheNe ---
fn test_case_fhevm_ne_bool(cks: &ClientKey) {
    for &a in &EXTREME_BOOL {
        for &b in &EXTREME_BOOL {
            let enc_a = FheBool::encrypt(a, cks);
            let enc_b = FheBool::encrypt(b, cks);
            let r = enc_a.ne(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a != b);
            let r2 = enc_a.ne(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a != b);
        }
    }
}
fn test_case_fhevm_ne_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = enc_a.ne(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a != b);
            let r2 = enc_a.ne(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a != b);
        }
    }
}
fn test_case_fhevm_ne_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = enc_a.ne(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a != b);
            let r2 = enc_a.ne(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a != b);
        }
    }
}
fn test_case_fhevm_ne_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = enc_a.ne(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a != b);
            let r2 = enc_a.ne(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a != b);
        }
    }
}
fn test_case_fhevm_ne_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = enc_a.ne(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a != b);
            let r2 = enc_a.ne(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a != b);
        }
    }
}
fn test_case_fhevm_ne_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = enc_a.ne(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a != b);
            let r2 = enc_a.ne(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a != b);
        }
    }
}
fn test_case_fhevm_ne_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        for b in extreme_u256() {
            let enc_a = FheUint256::encrypt(a, cks);
            let enc_b = FheUint256::encrypt(b, cks);
            let r = enc_a.ne(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a != b);
            let r2 = enc_a.ne(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a != b);
        }
    }
}
fn test_case_fhevm_ne_u160(cks: &ClientKey) {
    for a in extreme_u160() {
        for b in extreme_u160() {
            let enc_a = FheUint160::encrypt(a, cks);
            let enc_b = FheUint160::encrypt(b, cks);
            let r = enc_a.ne(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a != b);
            let r2 = enc_a.ne(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a != b);
        }
    }
}

#[test]
fn test_fhevm_gpu_ne_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ne_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ne_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ne_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ne_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ne_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ne_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ne_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ne_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ne_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ne_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ne_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ne_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ne_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ne_u160() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ne_u160(&cks);
    }
}

// --- fheGe ---
fn test_case_fhevm_ge_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = enc_a.ge(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a >= b);
            let r2 = enc_a.ge(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a >= b);
        }
    }
}
fn test_case_fhevm_ge_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = enc_a.ge(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a >= b);
            let r2 = enc_a.ge(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a >= b);
        }
    }
}
fn test_case_fhevm_ge_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = enc_a.ge(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a >= b);
            let r2 = enc_a.ge(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a >= b);
        }
    }
}
fn test_case_fhevm_ge_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = enc_a.ge(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a >= b);
            let r2 = enc_a.ge(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a >= b);
        }
    }
}
fn test_case_fhevm_ge_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = enc_a.ge(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a >= b);
            let r2 = enc_a.ge(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a >= b);
        }
    }
}

#[test]
fn test_fhevm_gpu_ge_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ge_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ge_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ge_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ge_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ge_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ge_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ge_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ge_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ge_u128(&cks);
    }
}

// --- fheGt ---
fn test_case_fhevm_gt_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = enc_a.gt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a > b);
            let r2 = enc_a.gt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a > b);
        }
    }
}
fn test_case_fhevm_gt_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = enc_a.gt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a > b);
            let r2 = enc_a.gt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a > b);
        }
    }
}
fn test_case_fhevm_gt_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = enc_a.gt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a > b);
            let r2 = enc_a.gt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a > b);
        }
    }
}
fn test_case_fhevm_gt_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = enc_a.gt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a > b);
            let r2 = enc_a.gt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a > b);
        }
    }
}
fn test_case_fhevm_gt_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = enc_a.gt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a > b);
            let r2 = enc_a.gt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a > b);
        }
    }
}

#[test]
fn test_fhevm_gpu_gt_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_gt_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_gt_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_gt_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_gt_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_gt_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_gt_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_gt_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_gt_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_gt_u128(&cks);
    }
}

// --- fheLe ---
fn test_case_fhevm_le_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = enc_a.le(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a <= b);
            let r2 = enc_a.le(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a <= b);
        }
    }
}
fn test_case_fhevm_le_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = enc_a.le(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a <= b);
            let r2 = enc_a.le(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a <= b);
        }
    }
}
fn test_case_fhevm_le_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = enc_a.le(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a <= b);
            let r2 = enc_a.le(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a <= b);
        }
    }
}
fn test_case_fhevm_le_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = enc_a.le(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a <= b);
            let r2 = enc_a.le(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a <= b);
        }
    }
}
fn test_case_fhevm_le_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = enc_a.le(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a <= b);
            let r2 = enc_a.le(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a <= b);
        }
    }
}

#[test]
fn test_fhevm_gpu_le_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_le_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_le_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_le_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_le_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_le_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_le_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_le_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_le_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_le_u128(&cks);
    }
}

// --- fheLt ---
fn test_case_fhevm_lt_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = enc_a.lt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a < b);
            let r2 = enc_a.lt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a < b);
        }
    }
}
fn test_case_fhevm_lt_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = enc_a.lt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a < b);
            let r2 = enc_a.lt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a < b);
        }
    }
}
fn test_case_fhevm_lt_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = enc_a.lt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a < b);
            let r2 = enc_a.lt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a < b);
        }
    }
}
fn test_case_fhevm_lt_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = enc_a.lt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a < b);
            let r2 = enc_a.lt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a < b);
        }
    }
}
fn test_case_fhevm_lt_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = enc_a.lt(&enc_b);
            let d: bool = r.decrypt(cks);
            assert_eq!(d, a < b);
            let r2 = enc_a.lt(b);
            let d2: bool = r2.decrypt(cks);
            assert_eq!(d2, a < b);
        }
    }
}

#[test]
fn test_fhevm_gpu_lt_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_lt_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_lt_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_lt_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_lt_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_lt_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_lt_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_lt_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_lt_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_lt_u128(&cks);
    }
}

// --- fheMin ---
fn test_case_fhevm_min_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = enc_a.min(&enc_b);
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a.min(b));
            let r2 = enc_a.min(b);
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, a.min(b));
        }
    }
}
fn test_case_fhevm_min_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = enc_a.min(&enc_b);
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a.min(b));
            let r2 = enc_a.min(b);
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, a.min(b));
        }
    }
}
fn test_case_fhevm_min_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = enc_a.min(&enc_b);
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a.min(b));
            let r2 = enc_a.min(b);
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a.min(b));
        }
    }
}
fn test_case_fhevm_min_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = enc_a.min(&enc_b);
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a.min(b));
            let r2 = enc_a.min(b);
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a.min(b));
        }
    }
}
fn test_case_fhevm_min_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = enc_a.min(&enc_b);
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a.min(b));
            let r2 = enc_a.min(b);
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a.min(b));
        }
    }
}

#[test]
fn test_fhevm_gpu_min_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_min_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_min_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_min_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_min_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_min_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_min_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_min_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_min_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_min_u128(&cks);
    }
}

// --- fheMax ---
fn test_case_fhevm_max_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &EXTREME_U8 {
            let enc_a = FheUint8::encrypt(a, cks);
            let enc_b = FheUint8::encrypt(b, cks);
            let r = enc_a.max(&enc_b);
            check_uint_noise(&r, cks);
            let d: u8 = r.decrypt(cks);
            assert_eq!(d, a.max(b));
            let r2 = enc_a.max(b);
            check_uint_noise(&r2, cks);
            let d2: u8 = r2.decrypt(cks);
            assert_eq!(d2, a.max(b));
        }
    }
}
fn test_case_fhevm_max_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &EXTREME_U16 {
            let enc_a = FheUint16::encrypt(a, cks);
            let enc_b = FheUint16::encrypt(b, cks);
            let r = enc_a.max(&enc_b);
            check_uint16_noise(&r, cks);
            let d: u16 = r.decrypt(cks);
            assert_eq!(d, a.max(b));
            let r2 = enc_a.max(b);
            check_uint16_noise(&r2, cks);
            let d2: u16 = r2.decrypt(cks);
            assert_eq!(d2, a.max(b));
        }
    }
}
fn test_case_fhevm_max_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &EXTREME_U32 {
            let enc_a = FheUint32::encrypt(a, cks);
            let enc_b = FheUint32::encrypt(b, cks);
            let r = enc_a.max(&enc_b);
            check_uint32_noise(&r, cks);
            let d: u32 = r.decrypt(cks);
            assert_eq!(d, a.max(b));
            let r2 = enc_a.max(b);
            check_uint32_noise(&r2, cks);
            let d2: u32 = r2.decrypt(cks);
            assert_eq!(d2, a.max(b));
        }
    }
}
fn test_case_fhevm_max_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &EXTREME_U64 {
            let enc_a = FheUint64::encrypt(a, cks);
            let enc_b = FheUint64::encrypt(b, cks);
            let r = enc_a.max(&enc_b);
            check_uint64_noise(&r, cks);
            let d: u64 = r.decrypt(cks);
            assert_eq!(d, a.max(b));
            let r2 = enc_a.max(b);
            check_uint64_noise(&r2, cks);
            let d2: u64 = r2.decrypt(cks);
            assert_eq!(d2, a.max(b));
        }
    }
}
fn test_case_fhevm_max_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        for &b in &EXTREME_U128 {
            let enc_a = FheUint128::encrypt(a, cks);
            let enc_b = FheUint128::encrypt(b, cks);
            let r = enc_a.max(&enc_b);
            check_uint128_noise(&r, cks);
            let d: u128 = r.decrypt(cks);
            assert_eq!(d, a.max(b));
            let r2 = enc_a.max(b);
            check_uint128_noise(&r2, cks);
            let d2: u128 = r2.decrypt(cks);
            assert_eq!(d2, a.max(b));
        }
    }
}

#[test]
fn test_fhevm_gpu_max_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_max_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_max_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_max_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_max_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_max_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_max_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_max_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_max_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_max_u128(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 20: fheNeg (T ∈ N = {u8..u256})
// ---------------------------------------------------------------------------

fn test_case_fhevm_neg_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        let enc_a = FheUint8::encrypt(a, cks);
        let r = -&enc_a;
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_neg());
    }
}
fn test_case_fhevm_neg_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        let enc_a = FheUint16::encrypt(a, cks);
        let r = -&enc_a;
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_neg());
    }
}
fn test_case_fhevm_neg_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        let enc_a = FheUint32::encrypt(a, cks);
        let r = -&enc_a;
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_neg());
    }
}
fn test_case_fhevm_neg_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        let enc_a = FheUint64::encrypt(a, cks);
        let r = -&enc_a;
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_neg());
    }
}
fn test_case_fhevm_neg_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        let enc_a = FheUint128::encrypt(a, cks);
        let r = -&enc_a;
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_neg());
    }
}
fn test_case_fhevm_neg_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        let enc_a = FheUint256::encrypt(a, cks);
        let r = -&enc_a;
        check_uint256_noise(&r, cks);
        let d: U256 = r.decrypt(cks);
        let expected = U256::ZERO.wrapping_sub(a);
        assert_eq!(d, expected);
    }
}

#[test]
fn test_fhevm_gpu_neg_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_neg_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_neg_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_neg_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_neg_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_neg_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_neg_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_neg_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_neg_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_neg_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_neg_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_neg_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 21: fheNot (T ∈ B ∪ N = {bool, u8..u256})
// ---------------------------------------------------------------------------

fn test_case_fhevm_not_bool(cks: &ClientKey) {
    for &a in &EXTREME_BOOL {
        let enc_a = FheBool::encrypt(a, cks);
        let r = !&enc_a;
        let d: bool = r.decrypt(cks);
        assert_eq!(d, !a);
    }
}
fn test_case_fhevm_not_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        let enc_a = FheUint8::encrypt(a, cks);
        let r = !&enc_a;
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        assert_eq!(d, !a);
    }
}
fn test_case_fhevm_not_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        let enc_a = FheUint16::encrypt(a, cks);
        let r = !&enc_a;
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        assert_eq!(d, !a);
    }
}
fn test_case_fhevm_not_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        let enc_a = FheUint32::encrypt(a, cks);
        let r = !&enc_a;
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        assert_eq!(d, !a);
    }
}
fn test_case_fhevm_not_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        let enc_a = FheUint64::encrypt(a, cks);
        let r = !&enc_a;
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        assert_eq!(d, !a);
    }
}
fn test_case_fhevm_not_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        let enc_a = FheUint128::encrypt(a, cks);
        let r = !&enc_a;
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        assert_eq!(d, !a);
    }
}
fn test_case_fhevm_not_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        let enc_a = FheUint256::encrypt(a, cks);
        let r = !&enc_a;
        check_uint256_noise(&r, cks);
        let d: U256 = r.decrypt(cks);
        assert_eq!(d, !a);
    }
}

#[test]
fn test_fhevm_gpu_not_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_not_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_not_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_not_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_not_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_not_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_not_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_not_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_not_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_not_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_not_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_not_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_not_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_not_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 23: cast  (36 pairs covering bool ↔ u8/u16/u32/u64/u128/u256)
// ---------------------------------------------------------------------------

fn test_case_fhevm_cast_bool_to_u8(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_BOOL {
        let enc_a = FheBool::encrypt(a, cks);
        let r = FheUint8::cast_from(enc_a.clone());
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        assert_eq!(d, u8::from(a));
    }
}
fn test_case_fhevm_cast_bool_to_u16(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_BOOL {
        let enc_a = FheBool::encrypt(a, cks);
        let r = FheUint16::cast_from(enc_a.clone());
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        assert_eq!(d, u16::from(a));
    }
}
fn test_case_fhevm_cast_bool_to_u32(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_BOOL {
        let enc_a = FheBool::encrypt(a, cks);
        let r = FheUint32::cast_from(enc_a.clone());
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        assert_eq!(d, u32::from(a));
    }
}
fn test_case_fhevm_cast_bool_to_u64(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_BOOL {
        let enc_a = FheBool::encrypt(a, cks);
        let r = FheUint64::cast_from(enc_a.clone());
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        assert_eq!(d, u64::from(a));
    }
}
fn test_case_fhevm_cast_bool_to_u128(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_BOOL {
        let enc_a = FheBool::encrypt(a, cks);
        let r = FheUint128::cast_from(enc_a.clone());
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        assert_eq!(d, u128::from(a));
    }
}
fn test_case_fhevm_cast_bool_to_u256(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_BOOL {
        let enc_a = FheBool::encrypt(a, cks);
        let r = FheUint256::cast_from(enc_a.clone());
        check_uint256_noise(&r, cks);
        let d: U256 = r.decrypt(cks);
        assert_eq!(d, U256::from(u64::from(a)));
    }
}
fn test_case_fhevm_cast_u8_to_bool(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        let enc_a = FheUint8::encrypt(a, cks);
        let r = enc_a.ne(0u8);
        let d: bool = r.decrypt(cks);
        assert_eq!(d, a != 0);
    }
}
fn test_case_fhevm_cast_u8_to_u16(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U8 {
        let enc_a = FheUint8::encrypt(a, cks);
        let r = FheUint16::cast_from(enc_a.clone());
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        assert_eq!(d, u16::from(a));
    }
}
fn test_case_fhevm_cast_u8_to_u32(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U8 {
        let enc_a = FheUint8::encrypt(a, cks);
        let r = FheUint32::cast_from(enc_a.clone());
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        assert_eq!(d, u32::from(a));
    }
}
fn test_case_fhevm_cast_u16_to_u8(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U16 {
        let enc_a = FheUint16::encrypt(a, cks);
        let r = FheUint8::cast_from(enc_a.clone());
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        assert_eq!(d, a as u8);
    }
}
fn test_case_fhevm_cast_u16_to_u32(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U16 {
        let enc_a = FheUint16::encrypt(a, cks);
        let r = FheUint32::cast_from(enc_a.clone());
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        assert_eq!(d, u32::from(a));
    }
}
fn test_case_fhevm_cast_u32_to_u8(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U32 {
        let enc_a = FheUint32::encrypt(a, cks);
        let r = FheUint8::cast_from(enc_a.clone());
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        assert_eq!(d, a as u8);
    }
}
fn test_case_fhevm_cast_u32_to_u64(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U32 {
        let enc_a = FheUint32::encrypt(a, cks);
        let r = FheUint64::cast_from(enc_a.clone());
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        assert_eq!(d, u64::from(a));
    }
}
fn test_case_fhevm_cast_u64_to_u32(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U64 {
        let enc_a = FheUint64::encrypt(a, cks);
        let r = FheUint32::cast_from(enc_a.clone());
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        assert_eq!(d, a as u32);
    }
}
fn test_case_fhevm_cast_u64_to_u128(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U64 {
        let enc_a = FheUint64::encrypt(a, cks);
        let r = FheUint128::cast_from(enc_a.clone());
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        assert_eq!(d, u128::from(a));
    }
}
fn test_case_fhevm_cast_u128_to_u64(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U128 {
        let enc_a = FheUint128::encrypt(a, cks);
        let r = FheUint64::cast_from(enc_a.clone());
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        assert_eq!(d, a as u64);
    }
}
fn test_case_fhevm_cast_u128_to_u256(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U128 {
        let enc_a = FheUint128::encrypt(a, cks);
        let r = FheUint256::cast_from(enc_a.clone());
        check_uint256_noise(&r, cks);
        let d: U256 = r.decrypt(cks);
        assert_eq!(d, U256::from(a));
    }
}
fn test_case_fhevm_cast_u256_to_u8(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for a in extreme_u256() {
        let enc_a = FheUint256::encrypt(a, cks);
        let r = FheUint8::cast_from(enc_a.clone());
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        assert_eq!(d, a.0[0] as u8);
    }
}
fn test_case_fhevm_cast_u8_to_u64(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U8 {
        let enc_a = FheUint8::encrypt(a, cks);
        let r = FheUint64::cast_from(enc_a.clone());
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        assert_eq!(d, u64::from(a));
    }
}
fn test_case_fhevm_cast_u8_to_u128(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U8 {
        let enc_a = FheUint8::encrypt(a, cks);
        let r = FheUint128::cast_from(enc_a.clone());
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        assert_eq!(d, u128::from(a));
    }
}
fn test_case_fhevm_cast_u8_to_u256(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U8 {
        let enc_a = FheUint8::encrypt(a, cks);
        let r = FheUint256::cast_from(enc_a.clone());
        check_uint256_noise(&r, cks);
        let d: U256 = r.decrypt(cks);
        assert_eq!(d, U256::from(a));
    }
}
fn test_case_fhevm_cast_u16_to_u64(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U16 {
        let enc_a = FheUint16::encrypt(a, cks);
        let r = FheUint64::cast_from(enc_a.clone());
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        assert_eq!(d, u64::from(a));
    }
}
fn test_case_fhevm_cast_u16_to_u128(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U16 {
        let enc_a = FheUint16::encrypt(a, cks);
        let r = FheUint128::cast_from(enc_a.clone());
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        assert_eq!(d, u128::from(a));
    }
}
fn test_case_fhevm_cast_u16_to_u256(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U16 {
        let enc_a = FheUint16::encrypt(a, cks);
        let r = FheUint256::cast_from(enc_a.clone());
        check_uint256_noise(&r, cks);
        let d: U256 = r.decrypt(cks);
        assert_eq!(d, U256::from(a));
    }
}
fn test_case_fhevm_cast_u32_to_u16(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U32 {
        let enc_a = FheUint32::encrypt(a, cks);
        let r = FheUint16::cast_from(enc_a.clone());
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        assert_eq!(d, a as u16);
    }
}
fn test_case_fhevm_cast_u32_to_u128(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U32 {
        let enc_a = FheUint32::encrypt(a, cks);
        let r = FheUint128::cast_from(enc_a.clone());
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        assert_eq!(d, u128::from(a));
    }
}
fn test_case_fhevm_cast_u32_to_u256(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U32 {
        let enc_a = FheUint32::encrypt(a, cks);
        let r = FheUint256::cast_from(enc_a.clone());
        check_uint256_noise(&r, cks);
        let d: U256 = r.decrypt(cks);
        assert_eq!(d, U256::from(a));
    }
}
fn test_case_fhevm_cast_u64_to_u8(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U64 {
        let enc_a = FheUint64::encrypt(a, cks);
        let r = FheUint8::cast_from(enc_a.clone());
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        assert_eq!(d, a as u8);
    }
}
fn test_case_fhevm_cast_u64_to_u16(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U64 {
        let enc_a = FheUint64::encrypt(a, cks);
        let r = FheUint16::cast_from(enc_a.clone());
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        assert_eq!(d, a as u16);
    }
}
fn test_case_fhevm_cast_u64_to_u256(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U64 {
        let enc_a = FheUint64::encrypt(a, cks);
        let r = FheUint256::cast_from(enc_a.clone());
        check_uint256_noise(&r, cks);
        let d: U256 = r.decrypt(cks);
        assert_eq!(d, U256::from(a));
    }
}
fn test_case_fhevm_cast_u128_to_u8(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U128 {
        let enc_a = FheUint128::encrypt(a, cks);
        let r = FheUint8::cast_from(enc_a.clone());
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        assert_eq!(d, a as u8);
    }
}
fn test_case_fhevm_cast_u128_to_u16(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U128 {
        let enc_a = FheUint128::encrypt(a, cks);
        let r = FheUint16::cast_from(enc_a.clone());
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        assert_eq!(d, a as u16);
    }
}
fn test_case_fhevm_cast_u128_to_u32(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for &a in &EXTREME_U128 {
        let enc_a = FheUint128::encrypt(a, cks);
        let r = FheUint32::cast_from(enc_a.clone());
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        assert_eq!(d, a as u32);
    }
}
fn test_case_fhevm_cast_u256_to_u16(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for a in extreme_u256() {
        let enc_a = FheUint256::encrypt(a, cks);
        let r = FheUint16::cast_from(enc_a.clone());
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        assert_eq!(d, a.0[0] as u16);
    }
}
fn test_case_fhevm_cast_u256_to_u32(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for a in extreme_u256() {
        let enc_a = FheUint256::encrypt(a, cks);
        let r = FheUint32::cast_from(enc_a.clone());
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        assert_eq!(d, a.0[0] as u32);
    }
}
fn test_case_fhevm_cast_u256_to_u64(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for a in extreme_u256() {
        let enc_a = FheUint256::encrypt(a, cks);
        let r = FheUint64::cast_from(enc_a.clone());
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        assert_eq!(d, a.0[0]);
    }
}
fn test_case_fhevm_cast_u256_to_u128(cks: &ClientKey) {
    use crate::core_crypto::prelude::CastFrom;
    for a in extreme_u256() {
        let enc_a = FheUint256::encrypt(a, cks);
        let r = FheUint128::cast_from(enc_a.clone());
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        assert_eq!(d, a.to_low_high_u128().0);
    }
}

#[test]
fn test_fhevm_gpu_cast_bool_to_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_bool_to_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_bool_to_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_bool_to_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_bool_to_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_bool_to_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_bool_to_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_bool_to_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_bool_to_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_bool_to_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_bool_to_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_bool_to_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u8_to_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u8_to_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u8_to_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u8_to_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u8_to_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u8_to_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u16_to_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u16_to_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u16_to_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u16_to_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u32_to_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u32_to_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u32_to_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u32_to_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u64_to_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u64_to_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u64_to_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u64_to_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u128_to_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u128_to_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u128_to_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u128_to_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u256_to_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u256_to_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u8_to_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u8_to_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u8_to_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u8_to_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u8_to_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u8_to_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u16_to_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u16_to_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u16_to_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u16_to_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u16_to_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u16_to_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u32_to_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u32_to_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u32_to_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u32_to_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u32_to_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u32_to_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u64_to_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u64_to_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u64_to_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u64_to_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u64_to_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u64_to_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u128_to_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u128_to_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u128_to_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u128_to_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u128_to_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u128_to_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u256_to_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u256_to_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u256_to_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u256_to_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u256_to_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u256_to_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_cast_u256_to_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_cast_u256_to_u128(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 24: trivialEncrypt then verify with fheAdd/fheEq  T ∈ H
// ---------------------------------------------------------------------------

fn test_case_fhevm_trivial_bool(cks: &ClientKey) {
    for &a in &EXTREME_BOOL {
        let triv = FheBool::encrypt_trivial(a);
        let enc = FheBool::encrypt(a, cks);
        // Use eq to verify trivial behaves correctly
        let r = triv.eq(&enc);
        let d: bool = r.decrypt(cks);
        assert!(d);
    }
}
fn test_case_fhevm_trivial_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        let triv = FheUint8::encrypt_trivial(a);
        let enc = FheUint8::encrypt(a, cks);
        let r = &triv + &enc;
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_add(a));
    }
}
fn test_case_fhevm_trivial_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        let triv = FheUint16::encrypt_trivial(a);
        let enc = FheUint16::encrypt(a, cks);
        let r = &triv + &enc;
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_add(a));
    }
}
fn test_case_fhevm_trivial_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        let triv = FheUint32::encrypt_trivial(a);
        let enc = FheUint32::encrypt(a, cks);
        let r = &triv + &enc;
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_add(a));
    }
}
fn test_case_fhevm_trivial_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        let triv = FheUint64::encrypt_trivial(a);
        let enc = FheUint64::encrypt(a, cks);
        let r = &triv + &enc;
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_add(a));
    }
}
fn test_case_fhevm_trivial_u128(cks: &ClientKey) {
    for &a in &EXTREME_U128 {
        let triv = FheUint128::encrypt_trivial(a);
        let enc = FheUint128::encrypt(a, cks);
        let r = &triv + &enc;
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        assert_eq!(d, a.wrapping_add(a));
    }
}
fn test_case_fhevm_trivial_u256(cks: &ClientKey) {
    for a in extreme_u256() {
        let triv = FheUint256::encrypt_trivial(a);
        let enc = FheUint256::encrypt(a, cks);
        let r = &triv + &enc;
        check_uint256_noise(&r, cks);
        let d: U256 = r.decrypt(cks);
        assert_eq!(d, a + a);
    }
}
fn test_case_fhevm_trivial_u160(cks: &ClientKey) {
    for a in extreme_u160() {
        let triv = FheUint160::encrypt_trivial(a);
        let enc = FheUint160::encrypt(a, cks);
        let r = triv.eq(&enc);
        let d: bool = r.decrypt(cks);
        assert!(d);
    }
}

#[test]
fn test_fhevm_gpu_trivial_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_trivial_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_trivial_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_trivial_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_trivial_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_trivial_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_trivial_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_trivial_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_trivial_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_trivial_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_trivial_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_trivial_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_trivial_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_trivial_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_trivial_u160() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_trivial_u160(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 25: fheIfThenElse  T ∈ H
// ---------------------------------------------------------------------------

fn test_case_fhevm_ite_bool(cks: &ClientKey) {
    for &ctrl in &EXTREME_BOOL {
        for &a in &EXTREME_BOOL {
            for &b in &EXTREME_BOOL {
                let enc_ctrl = FheBool::encrypt(ctrl, cks);
                let enc_a = FheBool::encrypt(a, cks);
                let enc_b = FheBool::encrypt(b, cks);
                let r = enc_ctrl.select(&enc_a, &enc_b);
                let d: bool = r.decrypt(cks);
                let expected = if ctrl { a } else { b };
                assert_eq!(d, expected);
            }
        }
    }
}
fn test_case_fhevm_ite_u8(cks: &ClientKey) {
    for &ctrl in &EXTREME_BOOL {
        for &a in &[0u8, 1, 127, 255] {
            for &b in &[0u8, 1, 127, 255] {
                let enc_ctrl = FheBool::encrypt(ctrl, cks);
                let enc_a = FheUint8::encrypt(a, cks);
                let enc_b = FheUint8::encrypt(b, cks);
                let r = enc_ctrl.select(&enc_a, &enc_b);
                check_uint_noise(&r, cks);
                let d: u8 = r.decrypt(cks);
                assert_eq!(d, if ctrl { a } else { b });
            }
        }
    }
}
fn test_case_fhevm_ite_u16(cks: &ClientKey) {
    for &ctrl in &EXTREME_BOOL {
        for &a in &[0u16, 1, 0x8000, 0xFFFF] {
            for &b in &[0u16, 1, 0x8000, 0xFFFF] {
                let enc_ctrl = FheBool::encrypt(ctrl, cks);
                let enc_a = FheUint16::encrypt(a, cks);
                let enc_b = FheUint16::encrypt(b, cks);
                let r = enc_ctrl.select(&enc_a, &enc_b);
                check_uint16_noise(&r, cks);
                let d: u16 = r.decrypt(cks);
                assert_eq!(d, if ctrl { a } else { b });
            }
        }
    }
}
fn test_case_fhevm_ite_u32(cks: &ClientKey) {
    for &ctrl in &EXTREME_BOOL {
        for &a in &[0u32, 1, 0x8000_0000, 0xFFFF_FFFF] {
            for &b in &[0u32, 1, 0x8000_0000, 0xFFFF_FFFF] {
                let enc_ctrl = FheBool::encrypt(ctrl, cks);
                let enc_a = FheUint32::encrypt(a, cks);
                let enc_b = FheUint32::encrypt(b, cks);
                let r = enc_ctrl.select(&enc_a, &enc_b);
                check_uint32_noise(&r, cks);
                let d: u32 = r.decrypt(cks);
                assert_eq!(d, if ctrl { a } else { b });
            }
        }
    }
}
fn test_case_fhevm_ite_u64(cks: &ClientKey) {
    for &ctrl in &EXTREME_BOOL {
        for &a in &[0u64, 1, u64::MAX / 2, u64::MAX] {
            for &b in &[0u64, 1, u64::MAX / 2, u64::MAX] {
                let enc_ctrl = FheBool::encrypt(ctrl, cks);
                let enc_a = FheUint64::encrypt(a, cks);
                let enc_b = FheUint64::encrypt(b, cks);
                let r = enc_ctrl.select(&enc_a, &enc_b);
                check_uint64_noise(&r, cks);
                let d: u64 = r.decrypt(cks);
                assert_eq!(d, if ctrl { a } else { b });
            }
        }
    }
}
fn test_case_fhevm_ite_u128(cks: &ClientKey) {
    for &ctrl in &EXTREME_BOOL {
        for &a in &[0u128, 1, u128::MAX / 2, u128::MAX] {
            for &b in &[0u128, 1, u128::MAX / 2, u128::MAX] {
                let enc_ctrl = FheBool::encrypt(ctrl, cks);
                let enc_a = FheUint128::encrypt(a, cks);
                let enc_b = FheUint128::encrypt(b, cks);
                let r = enc_ctrl.select(&enc_a, &enc_b);
                check_uint128_noise(&r, cks);
                let d: u128 = r.decrypt(cks);
                assert_eq!(d, if ctrl { a } else { b });
            }
        }
    }
}
fn test_case_fhevm_ite_u256(cks: &ClientKey) {
    let vals = [
        U256::ZERO,
        U256::ONE,
        U256::MAX / U256::from(2u64),
        U256::MAX,
    ];
    for &ctrl in &EXTREME_BOOL {
        for &a in &vals {
            for &b in &vals {
                let enc_ctrl = FheBool::encrypt(ctrl, cks);
                let enc_a = FheUint256::encrypt(a, cks);
                let enc_b = FheUint256::encrypt(b, cks);
                let r = enc_ctrl.select(&enc_a, &enc_b);
                check_uint256_noise(&r, cks);
                let d: U256 = r.decrypt(cks);
                assert_eq!(d, if ctrl { a } else { b });
            }
        }
    }
}
fn test_case_fhevm_ite_u160(cks: &ClientKey) {
    let mask160 = (U256::ONE << 160u32) - U256::ONE;
    let vals = [U256::ZERO, U256::ONE, U256::from(0xDEAD_BEEFu64), mask160];
    for &ctrl in &EXTREME_BOOL {
        for &a in &vals {
            for &b in &vals {
                let enc_ctrl = FheBool::encrypt(ctrl, cks);
                let enc_a = FheUint160::encrypt(a, cks);
                let enc_b = FheUint160::encrypt(b, cks);
                let r = enc_ctrl.select(&enc_a, &enc_b);
                check_uint160_noise(&r, cks);
                let d: U256 = r.decrypt(cks);
                assert_eq!(d, if ctrl { a } else { b });
            }
        }
    }
}

#[test]
fn test_fhevm_gpu_ite_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ite_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ite_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ite_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ite_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ite_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ite_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ite_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ite_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ite_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ite_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ite_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ite_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ite_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_ite_u160() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_ite_u160(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 26: fheRand  T ∈ {bool, u8..u256}
// ---------------------------------------------------------------------------

fn test_case_fhevm_rand_bool(cks: &ClientKey) {
    // Two same seeds give same result
    let r1 = FheBool::generate_oblivious_pseudo_random(Seed(42));
    let r2 = FheBool::generate_oblivious_pseudo_random(Seed(42));
    let d1: bool = r1.decrypt(cks);
    let d2: bool = r2.decrypt(cks);
    assert_eq!(d1, d2);
    // Different seeds — just verify decrypt works
    let _r3: bool = FheBool::generate_oblivious_pseudo_random(Seed(99)).decrypt(cks);
}
fn test_case_fhevm_rand_u8(cks: &ClientKey) {
    for seed in [0u128, 1, 2] {
        let r1 = FheUint8::generate_oblivious_pseudo_random(Seed(seed));
        let r2 = FheUint8::generate_oblivious_pseudo_random(Seed(seed));
        check_uint_noise(&r1, cks);
        let d1: u8 = r1.decrypt(cks);
        let d2: u8 = r2.decrypt(cks);
        assert_eq!(d1, d2);
    }
}
fn test_case_fhevm_rand_u16(cks: &ClientKey) {
    for seed in [0u128, 1, 2] {
        let r1 = FheUint16::generate_oblivious_pseudo_random(Seed(seed));
        let r2 = FheUint16::generate_oblivious_pseudo_random(Seed(seed));
        check_uint16_noise(&r1, cks);
        let d1: u16 = r1.decrypt(cks);
        let d2: u16 = r2.decrypt(cks);
        assert_eq!(d1, d2);
    }
}
fn test_case_fhevm_rand_u32(cks: &ClientKey) {
    for seed in [0u128, 1, 2] {
        let r1 = FheUint32::generate_oblivious_pseudo_random(Seed(seed));
        let r2 = FheUint32::generate_oblivious_pseudo_random(Seed(seed));
        check_uint32_noise(&r1, cks);
        let d1: u32 = r1.decrypt(cks);
        let d2: u32 = r2.decrypt(cks);
        assert_eq!(d1, d2);
    }
}
fn test_case_fhevm_rand_u64(cks: &ClientKey) {
    for seed in [0u128, 1, 2] {
        let r1 = FheUint64::generate_oblivious_pseudo_random(Seed(seed));
        let r2 = FheUint64::generate_oblivious_pseudo_random(Seed(seed));
        check_uint64_noise(&r1, cks);
        let d1: u64 = r1.decrypt(cks);
        let d2: u64 = r2.decrypt(cks);
        assert_eq!(d1, d2);
    }
}
fn test_case_fhevm_rand_u128(cks: &ClientKey) {
    for seed in [0u128, 1, 2] {
        let r1 = FheUint128::generate_oblivious_pseudo_random(Seed(seed));
        let r2 = FheUint128::generate_oblivious_pseudo_random(Seed(seed));
        check_uint128_noise(&r1, cks);
        let d1: u128 = r1.decrypt(cks);
        let d2: u128 = r2.decrypt(cks);
        assert_eq!(d1, d2);
    }
}
fn test_case_fhevm_rand_u256(cks: &ClientKey) {
    for seed in [0u128, 1, 2] {
        let r1 = FheUint256::generate_oblivious_pseudo_random(Seed(seed));
        let r2 = FheUint256::generate_oblivious_pseudo_random(Seed(seed));
        check_uint256_noise(&r1, cks);
        let d1: U256 = r1.decrypt(cks);
        let d2: U256 = r2.decrypt(cks);
        assert_eq!(d1, d2);
    }
}

#[test]
fn test_fhevm_gpu_rand_bool() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rand_bool(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rand_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rand_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rand_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rand_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rand_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rand_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rand_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rand_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rand_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rand_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_rand_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_rand_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 27: fheRandBounded  T ∈ {u8..u256}
// ---------------------------------------------------------------------------

fn test_case_fhevm_randbounded_u8(cks: &ClientKey) {
    for bits in [1u64, 2, 4, 7] {
        let r1 = FheUint8::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        let r2 = FheUint8::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        check_uint_noise(&r1, cks);
        let d1: u8 = r1.decrypt(cks);
        let d2: u8 = r2.decrypt(cks);
        assert_eq!(d1, d2);
        assert!(
            u64::from(d1) < (1u64 << bits),
            "randbounded_u8: {d1} >= 2^{bits}"
        );
    }
}
fn test_case_fhevm_randbounded_u16(cks: &ClientKey) {
    for bits in [1u64, 8, 14, 15] {
        let r1 = FheUint16::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        let r2 = FheUint16::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        check_uint16_noise(&r1, cks);
        let d1: u16 = r1.decrypt(cks);
        let d2: u16 = r2.decrypt(cks);
        assert_eq!(d1, d2);
        assert!(u64::from(d1) < (1u64 << bits));
    }
}
fn test_case_fhevm_randbounded_u32(cks: &ClientKey) {
    for bits in [1u64, 16, 30, 31] {
        let r1 = FheUint32::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        let r2 = FheUint32::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        check_uint32_noise(&r1, cks);
        let d1: u32 = r1.decrypt(cks);
        let d2: u32 = r2.decrypt(cks);
        assert_eq!(d1, d2);
        assert!(u64::from(d1) < (1u64 << bits));
    }
}
fn test_case_fhevm_randbounded_u64(cks: &ClientKey) {
    for bits in [1u64, 32, 62, 63] {
        let r1 = FheUint64::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        let r2 = FheUint64::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        check_uint64_noise(&r1, cks);
        let d1: u64 = r1.decrypt(cks);
        let d2: u64 = r2.decrypt(cks);
        assert_eq!(d1, d2);
        if bits < 64 {
            assert!(d1 < (1u64 << bits));
        }
    }
}
fn test_case_fhevm_randbounded_u128(cks: &ClientKey) {
    for bits in [1u64, 64, 126, 127] {
        let r1 = FheUint128::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        let r2 = FheUint128::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        check_uint128_noise(&r1, cks);
        let d1: u128 = r1.decrypt(cks);
        let d2: u128 = r2.decrypt(cks);
        assert_eq!(d1, d2);
        if bits < 128 {
            assert!(d1 < (1u128 << bits));
        }
    }
}
fn test_case_fhevm_randbounded_u256(cks: &ClientKey) {
    for bits in [1u64, 128, 254, 255] {
        let r1 = FheUint256::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        let r2 = FheUint256::generate_oblivious_pseudo_random_bounded(Seed(1), bits);
        check_uint256_noise(&r1, cks);
        let d1: U256 = r1.decrypt(cks);
        let d2: U256 = r2.decrypt(cks);
        assert_eq!(d1, d2);
        if bits < 256 {
            assert!(d1 < (U256::ONE << bits as u32));
        }
    }
}

#[test]
fn test_fhevm_gpu_randbounded_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_randbounded_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_randbounded_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_randbounded_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_randbounded_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_randbounded_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_randbounded_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_randbounded_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_randbounded_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_randbounded_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_randbounded_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_randbounded_u256(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 28: fheSum  T ∈ A = {u8..u128}
// ---------------------------------------------------------------------------

fn test_case_fhevm_sum_u8(cks: &ClientKey) {
    // spec §3: n=0 is valid and must produce encrypted zero
    let r: FheUint8 = std::iter::empty::<FheUint8>().sum();
    check_uint_noise(&r, cks);
    let d: u8 = r.decrypt(cks);
    assert_eq!(d, 0u8, "sum_u8: empty list must return 0");
    for size in [1usize, 2, 5] {
        let vals: Vec<u8> = (0..size)
            .map(|i| EXTREME_U8[i % EXTREME_U8.len()])
            .collect();
        let r: FheUint8 = vals.iter().map(|&v| FheUint8::encrypt(v, cks)).sum();
        check_uint_noise(&r, cks);
        let d: u8 = r.decrypt(cks);
        let expected: u8 = vals.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
        assert_eq!(d, expected, "sum_u8 size={size}");
    }
}
fn test_case_fhevm_sum_u16(cks: &ClientKey) {
    let r: FheUint16 = std::iter::empty::<FheUint16>().sum();
    check_uint16_noise(&r, cks);
    let d: u16 = r.decrypt(cks);
    assert_eq!(d, 0u16, "sum_u16: empty list must return 0");
    for size in [1usize, 2, 5] {
        let vals: Vec<u16> = (0..size)
            .map(|i| EXTREME_U16[i % EXTREME_U16.len()])
            .collect();
        let r: FheUint16 = vals.iter().map(|&v| FheUint16::encrypt(v, cks)).sum();
        check_uint16_noise(&r, cks);
        let d: u16 = r.decrypt(cks);
        let expected: u16 = vals.iter().fold(0u16, |acc, &x| acc.wrapping_add(x));
        assert_eq!(d, expected, "sum_u16 size={size}");
    }
}
fn test_case_fhevm_sum_u32(cks: &ClientKey) {
    let r: FheUint32 = std::iter::empty::<FheUint32>().sum();
    check_uint32_noise(&r, cks);
    let d: u32 = r.decrypt(cks);
    assert_eq!(d, 0u32, "sum_u32: empty list must return 0");
    for size in [1usize, 2, 5] {
        let vals: Vec<u32> = (0..size)
            .map(|i| EXTREME_U32[i % EXTREME_U32.len()])
            .collect();
        let r: FheUint32 = vals.iter().map(|&v| FheUint32::encrypt(v, cks)).sum();
        check_uint32_noise(&r, cks);
        let d: u32 = r.decrypt(cks);
        let expected: u32 = vals.iter().fold(0u32, |acc, &x| acc.wrapping_add(x));
        assert_eq!(d, expected, "sum_u32 size={size}");
    }
}
fn test_case_fhevm_sum_u64(cks: &ClientKey) {
    let r: FheUint64 = std::iter::empty::<FheUint64>().sum();
    check_uint64_noise(&r, cks);
    let d: u64 = r.decrypt(cks);
    assert_eq!(d, 0u64, "sum_u64: empty list must return 0");
    for size in [1usize, 2, 5] {
        let vals: Vec<u64> = (0..size)
            .map(|i| EXTREME_U64[i % EXTREME_U64.len()])
            .collect();
        let r: FheUint64 = vals.iter().map(|&v| FheUint64::encrypt(v, cks)).sum();
        check_uint64_noise(&r, cks);
        let d: u64 = r.decrypt(cks);
        let expected: u64 = vals.iter().fold(0u64, |acc, &x| acc.wrapping_add(x));
        assert_eq!(d, expected, "sum_u64 size={size}");
    }
}
fn test_case_fhevm_sum_u128(cks: &ClientKey) {
    let r: FheUint128 = std::iter::empty::<FheUint128>().sum();
    check_uint128_noise(&r, cks);
    let d: u128 = r.decrypt(cks);
    assert_eq!(d, 0u128, "sum_u128: empty list must return 0");
    for size in [1usize, 2, 5] {
        let vals: Vec<u128> = (0..size)
            .map(|i| EXTREME_U128[i % EXTREME_U128.len()])
            .collect();
        let r: FheUint128 = vals.iter().map(|&v| FheUint128::encrypt(v, cks)).sum();
        check_uint128_noise(&r, cks);
        let d: u128 = r.decrypt(cks);
        let expected: u128 = vals.iter().fold(0u128, |acc, &x| acc.wrapping_add(x));
        assert_eq!(d, expected, "sum_u128 size={size}");
    }
}

#[test]
fn test_fhevm_gpu_sum_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sum_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_sum_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sum_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_sum_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sum_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_sum_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sum_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_sum_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_sum_u128(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 29: fheIsIn  T ∈ N ∪ {u160}
// implemented as fold over eq
// ---------------------------------------------------------------------------

fn fhe_is_in_u8(enc_val: &FheUint8, set: &[u8]) -> FheBool {
    set.iter().fold(FheBool::encrypt_trivial(false), |acc, &v| {
        acc | enc_val.eq(v)
    })
}
fn fhe_is_in_u16(enc_val: &FheUint16, set: &[u16]) -> FheBool {
    set.iter().fold(FheBool::encrypt_trivial(false), |acc, &v| {
        acc | enc_val.eq(v)
    })
}
fn fhe_is_in_u32(enc_val: &FheUint32, set: &[u32]) -> FheBool {
    set.iter().fold(FheBool::encrypt_trivial(false), |acc, &v| {
        acc | enc_val.eq(v)
    })
}
fn fhe_is_in_u64(enc_val: &FheUint64, set: &[u64]) -> FheBool {
    set.iter().fold(FheBool::encrypt_trivial(false), |acc, &v| {
        acc | enc_val.eq(v)
    })
}
fn fhe_is_in_u128(enc_val: &FheUint128, set: &[u128]) -> FheBool {
    set.iter().fold(FheBool::encrypt_trivial(false), |acc, &v| {
        acc | enc_val.eq(v)
    })
}
fn fhe_is_in_u256(enc_val: &FheUint256, set: &[U256]) -> FheBool {
    set.iter().fold(FheBool::encrypt_trivial(false), |acc, &v| {
        acc | enc_val.eq(v)
    })
}
fn fhe_is_in_u160(enc_val: &FheUint160, set: &[U256]) -> FheBool {
    set.iter().fold(FheBool::encrypt_trivial(false), |acc, &v| {
        acc | enc_val.eq(v)
    })
}

fn test_case_fhevm_isin_u8(cks: &ClientKey) {
    let a = 42u8;
    let enc_a = FheUint8::encrypt(a, cks);
    // empty set -> false
    let r = fhe_is_in_u8(&enc_a, &[]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
    // set with element -> true
    let r = fhe_is_in_u8(&enc_a, &[10, 42, 100]);
    let d: bool = r.decrypt(cks);
    assert!(d);
    // set without element -> false
    let r = fhe_is_in_u8(&enc_a, &[10, 20, 100]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
}
fn test_case_fhevm_isin_u16(cks: &ClientKey) {
    let a = 1000u16;
    let enc_a = FheUint16::encrypt(a, cks);
    let r = fhe_is_in_u16(&enc_a, &[]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
    let r = fhe_is_in_u16(&enc_a, &[999, 1000, 1001]);
    let d: bool = r.decrypt(cks);
    assert!(d);
    let r = fhe_is_in_u16(&enc_a, &[1, 2, 3]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
}
fn test_case_fhevm_isin_u32(cks: &ClientKey) {
    let a = 0xDEAD_BEEFu32;
    let enc_a = FheUint32::encrypt(a, cks);
    let r = fhe_is_in_u32(&enc_a, &[]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
    let r = fhe_is_in_u32(&enc_a, &[0xDEAD_BEEF, 0]);
    let d: bool = r.decrypt(cks);
    assert!(d);
    let r = fhe_is_in_u32(&enc_a, &[0, 1]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
}
fn test_case_fhevm_isin_u64(cks: &ClientKey) {
    let a = 0xDEAD_BEEF_CAFE_C0DEu64;
    let enc_a = FheUint64::encrypt(a, cks);
    let r = fhe_is_in_u64(&enc_a, &[]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
    let r = fhe_is_in_u64(&enc_a, &[a, 0]);
    let d: bool = r.decrypt(cks);
    assert!(d);
    let r = fhe_is_in_u64(&enc_a, &[0, 1]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
}
fn test_case_fhevm_isin_u128(cks: &ClientKey) {
    let a = 0xDEAD_BEEF_CAFE_C0DE_1234_5678_9ABC_DEF0u128;
    let enc_a = FheUint128::encrypt(a, cks);
    let r = fhe_is_in_u128(&enc_a, &[]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
    let r = fhe_is_in_u128(&enc_a, &[a, 0]);
    let d: bool = r.decrypt(cks);
    assert!(d);
    let r = fhe_is_in_u128(&enc_a, &[0, 1]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
}
fn test_case_fhevm_isin_u256(cks: &ClientKey) {
    let a = U256::from((0xCAFE_C0DEu128, 0xDEAD_BEEFu128));
    let enc_a = FheUint256::encrypt(a, cks);
    let r = fhe_is_in_u256(&enc_a, &[]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
    let r = fhe_is_in_u256(&enc_a, &[a, U256::ZERO]);
    let d: bool = r.decrypt(cks);
    assert!(d);
    let r = fhe_is_in_u256(&enc_a, &[U256::ZERO, U256::ONE]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
}
fn test_case_fhevm_isin_u160(cks: &ClientKey) {
    let a = U256::from(0xABCD_EF01u64);
    let enc_a = FheUint160::encrypt(a, cks);
    let r = fhe_is_in_u160(&enc_a, &[]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
    let r = fhe_is_in_u160(&enc_a, &[a, U256::ZERO]);
    let d: bool = r.decrypt(cks);
    assert!(d);
    let r = fhe_is_in_u160(&enc_a, &[U256::ZERO, U256::ONE]);
    let d: bool = r.decrypt(cks);
    assert!(!d);
}

#[test]
fn test_fhevm_gpu_isin_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_isin_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_isin_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_isin_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_isin_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_isin_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_isin_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_isin_u64(&cks);
    }
}
#[test]
fn test_fhevm_gpu_isin_u128() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_isin_u128(&cks);
    }
}
#[test]
fn test_fhevm_gpu_isin_u256() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_isin_u256(&cks);
    }
}
#[test]
fn test_fhevm_gpu_isin_u160() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_isin_u160(&cks);
    }
}

// ---------------------------------------------------------------------------
// OPCODE 30: fheMulDiv  T ∈ {u8, u16, u32, u64}
// (&enc_a).fused_mul_scalar_div(&enc_b, div)  and
// (&enc_a).fused_scalar_mul_scalar_div(scalar_b, div)
// ---------------------------------------------------------------------------

use crate::high_level_api::traits::{FusedMulScalarDiv, FusedScalarMulScalarDiv};

fn test_case_fhevm_muldiv_u8(cks: &ClientKey) {
    for &a in &EXTREME_U8 {
        for &b in &DIVISORS_U8 {
            for &div in &DIVISORS_U8 {
                let enc_a = FheUint8::encrypt(a, cks);
                let enc_b = FheUint8::encrypt(b, cks);
                let r = (&enc_a).fused_mul_scalar_div(&enc_b, div);
                check_uint_noise(&r, cks);
                let d: u8 = r.decrypt(cks);
                let expected = ((a as u16 * b as u16) / div as u16) as u8;
                assert_eq!(d, expected, "muldiv_u8 ({a}*{b})/{div}");
                let r2 = (&enc_a).fused_scalar_mul_scalar_div(b, div);
                check_uint_noise(&r2, cks);
                let d2: u8 = r2.decrypt(cks);
                assert_eq!(d2, expected);
            }
        }
    }
}
fn test_case_fhevm_muldiv_u16(cks: &ClientKey) {
    for &a in &EXTREME_U16 {
        for &b in &DIVISORS_U16 {
            for &div in &DIVISORS_U16 {
                let enc_a = FheUint16::encrypt(a, cks);
                let enc_b = FheUint16::encrypt(b, cks);
                let r = (&enc_a).fused_mul_scalar_div(&enc_b, div);
                check_uint16_noise(&r, cks);
                let d: u16 = r.decrypt(cks);
                let expected = ((a as u32 * b as u32) / div as u32) as u16;
                assert_eq!(d, expected, "muldiv_u16 ({a}*{b})/{div}");
                let r2 = (&enc_a).fused_scalar_mul_scalar_div(b, div);
                check_uint16_noise(&r2, cks);
                let d2: u16 = r2.decrypt(cks);
                assert_eq!(d2, expected);
            }
        }
    }
}
fn test_case_fhevm_muldiv_u32(cks: &ClientKey) {
    for &a in &EXTREME_U32 {
        for &b in &DIVISORS_U32 {
            for &div in &DIVISORS_U32 {
                let enc_a = FheUint32::encrypt(a, cks);
                let enc_b = FheUint32::encrypt(b, cks);
                let r = (&enc_a).fused_mul_scalar_div(&enc_b, div);
                check_uint32_noise(&r, cks);
                let d: u32 = r.decrypt(cks);
                let expected = ((a as u64 * b as u64) / div as u64) as u32;
                assert_eq!(d, expected, "muldiv_u32 ({a}*{b})/{div}");
                let r2 = (&enc_a).fused_scalar_mul_scalar_div(b, div);
                check_uint32_noise(&r2, cks);
                let d2: u32 = r2.decrypt(cks);
                assert_eq!(d2, expected);
            }
        }
    }
}
fn test_case_fhevm_muldiv_u64(cks: &ClientKey) {
    for &a in &EXTREME_U64 {
        for &b in &DIVISORS_U64 {
            for &div in &DIVISORS_U64 {
                let enc_a = FheUint64::encrypt(a, cks);
                let enc_b = FheUint64::encrypt(b, cks);
                let r = (&enc_a).fused_mul_scalar_div(&enc_b, div);
                check_uint64_noise(&r, cks);
                let d: u64 = r.decrypt(cks);
                let expected = ((a as u128 * b as u128) / div as u128) as u64;
                assert_eq!(d, expected, "muldiv_u64 ({a}*{b})/{div}");
                let r2 = (&enc_a).fused_scalar_mul_scalar_div(b, div);
                check_uint64_noise(&r2, cks);
                let d2: u64 = r2.decrypt(cks);
                assert_eq!(d2, expected);
            }
        }
    }
}

#[test]
fn test_fhevm_gpu_muldiv_u8() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_muldiv_u8(&cks);
    }
}
#[test]
fn test_fhevm_gpu_muldiv_u16() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_muldiv_u16(&cks);
    }
}
#[test]
fn test_fhevm_gpu_muldiv_u32() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_muldiv_u32(&cks);
    }
}
#[test]
fn test_fhevm_gpu_muldiv_u64() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        test_case_fhevm_muldiv_u64(&cks);
    }
}
