mod shift_register;

pub mod kreyvium;

/// Pack `bits` into `bytes` LSB-first within each byte. `bytes` must be
/// zero-initialized and at least `bits.len().div_ceil(8)` long.
fn pack_bits_lsb_first(bits: &[bool], bytes: &mut [u8]) {
    for (i, &bit) in bits.iter().enumerate() {
        bytes[i / 8] |= (bit as u8) << (i % 8);
    }
}

/// Unpack `bytes` into `bits` LSB-first within each byte. `bits` must be at
/// least `bytes.len() * 8` long.
fn unpack_bits_lsb_first(bytes: &[u8], bits: &mut [bool]) {
    for (b, &byte) in bytes.iter().enumerate() {
        for j in 0..8 {
            bits[8 * b + j] = ((byte >> j) & 1) == 1;
        }
    }
}
