use rayon::prelude::*;
use tfhe::shortint::prelude::*;
use tfhe::shortint::server_key::LookupTableOwned;

use crate::tables;

/* Macro to monitor individual functions timings (feature related: "verbose-timings").
 * Evaluates to the return value of the monitored call. */
#[cfg(feature = "verbose-timings")]
macro_rules! monitor {
    ($fn:ident($( $a:expr ), *)) => {{
        let t0 = std::time::Instant::now();
        let res = $fn($( $a), *);
        eprintln!("{}:\t{:.4?}", stringify!($fn), t0.elapsed());
        res
    }}
}
#[cfg(not(feature = "verbose-timings"))]
macro_rules! monitor {
    ($fn:ident($( $a:expr ), *)) => { $fn($( $a), *) }
}

/* Nibble formats carried by the [Ciphertext; N] arrays
 * ------------------------------------------   u4   (16) - one full 4-bit nibble per ciphertext
 *   u2h  (32) - 2 bits per ciphertext, packed on the high bits (u2h = u2 << 2)
 *   u2l  (32) - 2 bits per ciphertext, on the low bits: the crate's input/output and key
 * encoding   bits (64) - a single bit per ciphertext, exact shifted position varies
 */

fn par_array_from_fn<const N: usize>(
    f: impl Fn(usize) -> Ciphertext + Send + Sync,
) -> [Ciphertext; N] {
    (0..N)
        .into_par_iter()
        .map(f)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Every lookup table here spans the whole 4-bit plaintext space, and the nibble formats above use
/// the carry bits to hold state, so the crate is tied to a 2-bit message / 2-bit carry parameter
/// set: any other splitting would truncate the S-box outputs or drop drifted bits.
fn assert_2_2_parameters(server_key: &ServerKey) {
    assert_eq!(
        (server_key.message_modulus, server_key.carry_modulus),
        (MessageModulus(4), CarryModulus(4)),
        "PRINCEv2 requires a 2-bit message / 2-bit carry parameter set, \
         e.g. PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128"
    );
}

fn build_lut(server_key: &ServerKey, table: &[u8; 1 << 4]) -> LookupTableOwned {
    server_key.generate_lookup_table(|x: u64| table[x as usize] as u64)
}

fn sum_adjacent_pairs<const N: usize>(
    server_key: &ServerKey,
    in_ct: &[Ciphertext],
) -> [Ciphertext; N] {
    assert_eq!(in_ct.len(), 2 * N);
    std::array::from_fn(|i| server_key.unchecked_add(&in_ct[2 * i], &in_ct[2 * i + 1]))
}

/// Sums the four ciphertexts of `in_ct` whose indexes are in `src_idx`.
fn sum_4_at(server_key: &ServerKey, in_ct: &[Ciphertext], src_idx: [usize; 4]) -> Ciphertext {
    let mut ct_sum: Ciphertext = server_key.unchecked_add(&in_ct[src_idx[0]], &in_ct[src_idx[1]]);
    server_key.unchecked_add_assign(&mut ct_sum, &in_ct[src_idx[2]]);
    server_key.unchecked_add_assign(&mut ct_sum, &in_ct[src_idx[3]]);
    ct_sum
}

fn sum_with_key(
    server_key: &ServerKey,
    in_u2h: &[Ciphertext; 32],
    ct_k: &[Ciphertext; 32],
) -> [Ciphertext; 32] {
    std::array::from_fn(|out_u2| server_key.unchecked_add(&in_u2h[out_u2], &ct_k[out_u2]))
}

fn sbox_to_u2h(
    server_key: &ServerKey,
    in_u4: &[Ciphertext; 16],
    lut_sbox: &[[u8; 1 << 4]; 16],
) -> [Ciphertext; 32] {
    par_array_from_fn(|out_u2| {
        let nibble = out_u2 >> 1;

        let extract_input_upper_half = out_u2 % 2 == 0;

        let in_shift = if extract_input_upper_half { 2 } else { 0 };

        let lut = server_key.generate_lookup_table(|x: u64| {
            let sbox_out: u8 = lut_sbox[nibble][x as usize];
            let u2: u8 = (sbox_out >> in_shift) & 0x3;
            (u2 << 2) as u64
        });
        server_key.apply_lookup_table(&in_u4[nibble], &lut)
    })
}

/// S-Boxes, 4-bit nibbles (16) --> single bits (64)
/// . each 4-bit nibble requires 4 applications of (same LUT + Bit extraction)
// [Parallel:64]
fn sbox_to_bits(
    server_key: &ServerKey,
    in_u4: &[Ciphertext; 16],
    lut_sbox: &[[u8; 1 << 4]; 16],
) -> [Ciphertext; 64] {
    par_array_from_fn(|out_bit| {
        let nibble = out_bit >> 2;

        let out_bit_index_in_nibble = 3 - (out_bit & 0x3);

        let sbox_out_bit_to_extract = out_bit_index_in_nibble;

        let out_shift = 3 - (nibble % 4);

        let lut = server_key.generate_lookup_table(|x: u64| {
            let sbox_out: u8 = lut_sbox[nibble][x as usize];
            let bit: u8 = (sbox_out >> sbox_out_bit_to_extract) & 0x1;
            (bit << out_shift) as u64
        });
        server_key.apply_lookup_table(&in_u4[nibble], &lut)
    })
}

/// M-layer: apply the e-xor matrices, then the FHE permutation `perm`.
/// `perm` is in gather form: `out[idx]` is the e-xor output of `in[perm[idx]]`
/// It carries the P-Layer on top of the M-Layer bit reordering when it is `FHE_MP_PERM_FW`.
// [Parallel:64]
fn m_layer(
    server_key: &ServerKey,
    in_u4: &[Ciphertext; 16],
    lut_exor: &[&[[u8; 1 << 4]; 4]],
    perm: &[usize; 64],
) -> [Ciphertext; 64] {
    par_array_from_fn(|out_bit| {
        let src_bit = perm[out_bit];

        let src_nibble = src_bit >> 2;

        let src_bit_idx_in_nibble = src_bit & 0x3;
        let exor_matrix = lut_exor[out_bit % lut_exor.len()];
        let lut = build_lut(server_key, &exor_matrix[src_bit_idx_in_nibble]);
        server_key.apply_lookup_table(&in_u4[src_nibble], &lut)
    })
}

/// Works independently on all groups of 4 nibbles
/// For each nibble in a group of 4, packs each of its bits with corresponding bits from the 3 other
/// nibbles
///
/// Bits are expected to already be shifted as to not collide
fn pack_bit_lanes_to_u4(server_key: &ServerKey, in_bits: &[Ciphertext; 64]) -> [Ciphertext; 16] {
    std::array::from_fn(|out_nibble| {
        let group = out_nibble >> 2;

        let out_nibble_idx_in_group = out_nibble & 0x3;

        let in_bit_idx: [usize; 4] = std::array::from_fn(|in_nibble_idx_in_group| {
            let in_nibble = 4 * group + in_nibble_idx_in_group;

            let in_bit_idx_in_nibble = out_nibble_idx_in_group;

            4 * in_nibble + in_bit_idx_in_nibble
        });

        sum_4_at(server_key, in_bits, in_bit_idx)
    })
}
/// Backward variant of [`pack_bit_lanes_to_u4`], with the  preceding nibble permutation folded into
/// the indices.
fn pack_bit_lanes_to_u4_inv_p(
    server_key: &ServerKey,
    in_bits: &[Ciphertext; 64],
) -> [Ciphertext; 16] {
    std::array::from_fn(|out_nibble| {
        let group = out_nibble >> 2;

        let out_nibble_idx_in_group = out_nibble & 0x3;

        let in_bit_idx: [usize; 4] = std::array::from_fn(|middle_nibble_idx_in_group| {
            // middle is the state after the permutation and before the bit lane packing
            let middle_nibble = 4 * group + middle_nibble_idx_in_group;

            let in_nibble = tables::INV_P_PERM[middle_nibble];

            let in_bit_idx_in_nibble = out_nibble_idx_in_group;

            4 * in_nibble + in_bit_idx_in_nibble
        });
        sum_4_at(server_key, in_bits, in_bit_idx)
    })
}

fn xor_to_u4(
    server_key: &ServerKey,
    in_u2h: &[Ciphertext; 32],
    ct_k: &[Ciphertext; 32],
) -> [Ciphertext; 16] {
    // xor alternatively to pairs of high/low bits
    let lut_xor_fw: [LookupTableOwned; 2] =
        std::array::from_fn(|i| build_lut(server_key, &tables::LUT_XOR_FW[i]));

    let ct_key_sum: [Ciphertext; 32] = sum_with_key(server_key, in_u2h, ct_k);
    // [Parallel:32] Apply xor LUT to high or low bit
    let ct_xor_halves: [Ciphertext; 32] = par_array_from_fn(|out_u2| {
        let idx_odd = out_u2 & 0x1;

        server_key.apply_lookup_table(&ct_key_sum[out_u2], &lut_xor_fw[idx_odd])
    });
    // [Parallel:16] Sum by pairs
    sum_adjacent_pairs(server_key, &ct_xor_halves)
}

/* returns (in_u2h xor ct_k) as vec of bits
 * [Parallel:(32)/64] -> drifted bits */
fn xor_to_bits(
    server_key: &ServerKey,
    in_u2h: &[Ciphertext; 32],
    ct_k: &[Ciphertext; 32],
) -> [Ciphertext; 64] {
    let luts_xor_bit_high: [LookupTableOwned; 4] =
        std::array::from_fn(|i| build_lut(server_key, &tables::LUT_XOR_BIT_HIGH[i]));
    let luts_xor_bit_low: [LookupTableOwned; 4] =
        std::array::from_fn(|i| build_lut(server_key, &tables::LUT_XOR_BIT_LOW[i]));

    let ct_key_sum: [Ciphertext; 32] = sum_with_key(server_key, in_u2h, ct_k);

    // apply xor (and bit_extract) luts on each nibble
    par_array_from_fn(|out_bit| {
        let nibble = out_bit >> 2;
        let is_low_bit = (out_bit & 0x1) == 1;

        let output_bit_index = nibble & 0x3;

        let lut_xor_bit = if is_low_bit {
            &luts_xor_bit_low[output_bit_index]
        } else {
            &luts_xor_bit_high[output_bit_index]
        };

        let in_u2 = out_bit >> 1;

        server_key.apply_lookup_table(&ct_key_sum[in_u2], lut_xor_bit)
    })
}

fn xor_to_u2l(
    server_key: &ServerKey,
    in_u2h: &[Ciphertext; 32],
    ct_k: &[Ciphertext; 32],
) -> [Ciphertext; 32] {
    let lut_xor = build_lut(server_key, &tables::LUT_XOR_TO_LOW);

    let ct_key_sum: [Ciphertext; 32] = sum_with_key(server_key, in_u2h, ct_k);
    // [Parallel:32] Apply xor luts on each nibble
    par_array_from_fn(|u2_idx| server_key.apply_lookup_table(&ct_key_sum[u2_idx], &lut_xor))
}

/// Forward round R = P-Layer . M-Layer . S-Layer
/// the P-Layer being fused into the M-layer gather
fn fw_round(
    server_key: &ServerKey,
    in_u4: &[Ciphertext; 16],
    lut_sbox: &[[u8; 1 << 4]; 16],
) -> [Ciphertext; 32] {
    let ct_sbox_bits: [Ciphertext; 64] = sbox_to_bits(server_key, in_u4, lut_sbox);
    let ct_mlayer_in_u4: [Ciphertext; 16] = pack_bit_lanes_to_u4(server_key, &ct_sbox_bits);
    let ct_mlayer_out_bits: [Ciphertext; 64] = m_layer(
        server_key,
        &ct_mlayer_in_u4,
        &tables::LUT_EXOR_FW,
        &tables::FHE_MP_PERM_FW,
    );

    /* Bridging M-Layer --> Xor: combine pairs */
    sum_adjacent_pairs(server_key, &ct_mlayer_out_bits)
}

/// Xor layer with `ct_k`, then a forward round.
fn xor_then_fw_round(
    server_key: &ServerKey,
    ct_u2h: &mut [Ciphertext; 32], // in/out: 2-bits (high)
    ct_k: &[Ciphertext; 32],
    lut_sbox: &[[u8; 1 << 4]; 16],
) {
    let ct_xor_u4: [Ciphertext; 16] = xor_to_u4(server_key, ct_u2h, ct_k);

    (*ct_u2h) = fw_round(server_key, &ct_xor_u4, lut_sbox);
}

/// Middle round R' = S-Layer^-1( k_after_m_layer + M-Layer( k_after_sbox + S-Layer(.) ) ).
/// Unlike the forward and backward rounds, it owns two of its key xors.
fn mid_round(
    server_key: &ServerKey,
    in_u4: &[Ciphertext; 16],
    ct_k_after_sbox: &[Ciphertext; 32],
    ct_k_after_m_layer: &[Ciphertext; 32],
    lut_sbox: &[[u8; 1 << 4]; 16],
    lut_inv_sbox: &[[u8; 1 << 4]; 16],
) -> [Ciphertext; 32] {
    // S-Boxes /!\ output for xor
    let ct_sbox_u2h: [Ciphertext; 32] = sbox_to_u2h(server_key, in_u4, lut_sbox);

    let ct_xor_bits: [Ciphertext; 64] = xor_to_bits(server_key, &ct_sbox_u2h, ct_k_after_sbox);

    let ct_mlayer_in_u4: [Ciphertext; 16] = pack_bit_lanes_to_u4(server_key, &ct_xor_bits);
    let ct_mlayer_out_bits: [Ciphertext; 64] = m_layer(
        server_key,
        &ct_mlayer_in_u4,
        &tables::LUT_EXOR_FW,
        &tables::FHE_M_PERM,
    );

    /* Bridging M-Layer --> Xor: combine pairs */
    let ct_mlayer_out_u2h: [Ciphertext; 32] = sum_adjacent_pairs(server_key, &ct_mlayer_out_bits);

    let ct_xor_u4: [Ciphertext; 16] = xor_to_u4(server_key, &ct_mlayer_out_u2h, ct_k_after_m_layer);

    sbox_to_u2h(server_key, &ct_xor_u4, lut_inv_sbox)
}

/// Xor layer with `ct_k`, then the middle round.
fn xor_then_mid_round(
    server_key: &ServerKey,
    ct_u2h: &mut [Ciphertext; 32], // in/out: 2-bits (high)
    ct_k: &[Ciphertext; 32],
    ct_k_after_sbox: &[Ciphertext; 32],
    ct_k_after_m_layer: &[Ciphertext; 32],
    lut_sbox: &[[u8; 1 << 4]; 16],
    lut_inv_sbox: &[[u8; 1 << 4]; 16],
) {
    let ct_xor_u4: [Ciphertext; 16] = xor_to_u4(server_key, ct_u2h, ct_k);

    (*ct_u2h) = mid_round(
        server_key,
        &ct_xor_u4,
        ct_k_after_sbox,
        ct_k_after_m_layer,
        lut_sbox,
        lut_inv_sbox,
    );
}

/// Backward round R^-1 = S-Layer^-1 . M-Layer^-1 . P-Layer^-1
/// the inverse P-Layer being fused into the M-layer gather
fn bw_round(
    server_key: &ServerKey,
    in_bits: &[Ciphertext; 64],
    lut_inv_sbox: &[[u8; 1 << 4]; 16],
) -> [Ciphertext; 32] {
    // iPerm + M-Layer
    let ct_mlayer_in_u4: [Ciphertext; 16] = pack_bit_lanes_to_u4_inv_p(server_key, in_bits);
    let ct_mlayer_out_bits: [Ciphertext; 64] = m_layer(
        server_key,
        &ct_mlayer_in_u4,
        &tables::LUT_EXOR_BW,
        &tables::FHE_M_PERM,
    );

    /* Bridging MLayer --> SBox: combine to u4 = sum[4*i:4*i+4] for i in range(16) */
    let ct_bit_pairs: [Ciphertext; 32] = sum_adjacent_pairs(server_key, &ct_mlayer_out_bits);
    let ct_sbox_in_u4: [Ciphertext; 16] = sum_adjacent_pairs(server_key, &ct_bit_pairs);

    sbox_to_u2h(server_key, &ct_sbox_in_u4, lut_inv_sbox)
}

/// Xor layer with `ct_k`, then a backward round.
fn xor_then_bw_round(
    server_key: &ServerKey,
    ct_u2h: &mut [Ciphertext; 32], // in/out: 2-bits (high)
    ct_k: &[Ciphertext; 32],
    lut_inv_sbox: &[[u8; 1 << 4]; 16],
) {
    let ct_xor_bits: [Ciphertext; 64] = xor_to_bits(server_key, ct_u2h, ct_k);

    (*ct_u2h) = bw_round(server_key, &ct_xor_bits, lut_inv_sbox);
}

/// Homomorphic PRINCEv2 encryption of one 64-bit block under the key `ct_k0 || ct_k1`.
///
/// Input message and keys are expected to carry 2 bits per ciphertext in the low bits of the message space,
/// most significant bits first (the `u2l` format of [`crate::encryption::encrypt_u64_as_u2l`]).
///
/// The output message also  carry 2 bits per ciphertext in the low bits of the message space and are have nominal noise/
#[rustfmt::skip] // [skip] Each monitor! call gets split on 5 lines which destroys readability
pub fn encrypt(
    server_key: &ServerKey,
    ct_m: &[Ciphertext; 32],
    ct_k0: &[Ciphertext; 32],
    ct_k1: &[Ciphertext; 32],
) -> [Ciphertext; 32] {
    assert_2_2_parameters(server_key);

    // Work buffer, in the u2h nibble format (u2h = u2 << 2). Each round xors its own key in.
    // [Parallel] + Init: ct_m << 2
    let mut ct_u2h: [Ciphertext; 32] =
        std::array::from_fn(|u2_idx| server_key.unchecked_scalar_mul(&ct_m[u2_idx], 4));

    // Keys are xored in strict alternation, starting with k0 (whitening) and ending with k1
    // Forward rounds
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_0_SBOX_0));
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_1_SBOX_2));
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_0_SBOX_0));
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_3_SBOX_4));
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_0_SBOX_0));
    // Middle round
    monitor!(xor_then_mid_round(server_key, &mut ct_u2h, ct_k1, ct_k0, ct_k1,
                           &tables::LUT_5_SBOX_MID, &tables::LUT_0_INV_SBOX_0));
    // Backward rounds
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_6_INV_SBOX_7));
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_0_INV_SBOX_0));
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_8_INV_SBOX_9));
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_0_INV_SBOX_0));
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_A_INV_SBOX_B));
    // Last Xor to u2l
    monitor!(xor_to_u2l(server_key, &ct_u2h, ct_k1))
}

/// Homomorphic PRINCEv2 decryption of one 64-bit block under the key `ct_k0 || ct_k1`.
///
/// Same formats and same requirement on the noise level of the inputs as [`encrypt`].
#[rustfmt::skip] // [skip] Each monitor! call gets split on 5 lines which destroys readability
pub fn decrypt(
    server_key: &ServerKey,
    ct_c: &[Ciphertext; 32],
    ct_k0: &[Ciphertext; 32],
    ct_k1: &[Ciphertext; 32],
) -> [Ciphertext; 32] {
    assert_2_2_parameters(server_key);

    // Work buffer, in the u2h nibble format (u2h = u2 << 2). Each round xors its own key in.
    // [Parallel] + Init: ct_c << 2
    let mut ct_u2h: [Ciphertext; 32] =
        std::array::from_fn(|u2_idx| server_key.unchecked_scalar_mul(&ct_c[u2_idx], 4));

    // Same alternation as encrypt(), with k0/k1 swapped: starts with k1, ends with k0
    // Forward rounds
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_B_SBOX_A));
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_0_SBOX_0));
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_9_SBOX_8));
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_0_SBOX_0));
    monitor!(xor_then_fw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_7_SBOX_6));
    // Middle round
    monitor!(xor_then_mid_round(server_key, &mut ct_u2h, ct_k0, ct_k1, ct_k0,
                           &tables::LUT_0_SBOX_0, &tables::LUT_MID_INV_SBOX_5));
    // Backward rounds
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_0_INV_SBOX_0));
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_4_INV_SBOX_3));
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_0_INV_SBOX_0));
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k0, &tables::LUT_2_INV_SBOX_1));
    monitor!(xor_then_bw_round(server_key, &mut ct_u2h, ct_k1, &tables::LUT_0_INV_SBOX_0));
    // Last Xor to u2l
    monitor!(xor_to_u2l(server_key, &ct_u2h, ct_k0))
}
