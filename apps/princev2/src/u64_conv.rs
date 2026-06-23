/*
 * Some bit manipulation converting u64 to vectors of 2/4-bit nibbles
 * ----------------------------------------------------------------------------------------------- */

// u64 -> [u4; 16], res[0] = 4 MSB bits of u64
pub const fn u64_to_vec_u4(u: u64) -> [u8; 64 / 4] {
    let mut i: usize = 0;
    let mut v: [u8; 64 / 4] = [0; 64 / 4];

    // "for" loop is unusable inside const
    while i < 64 / 4 {
        v[64 / 4 - i - 1] = ((u >> (4 * i)) & 0xf) as u8;
        i += 1;
    }
    v
}

#[allow(dead_code)] // kept for symmetry with u64_to_vec_u4(); might be useful to convert back decomposed constants
pub const fn vec_u4_to_u64(v: [u8; 64 / 4]) -> u64 {
    let mut i: usize = 0;
    let mut u: u64 = 0;

    // "for" loop is unusable inside const
    while i < 64 / 4 {
        u += (v[i] as u64) << (60 - 4 * i);
        i += 1;
    }
    u
}

#[test]
fn test_u64_conv_vec_u4() {
    let u: u64 = 0x3f84d5b5b5470917;
    let u_dec: [u8; 16] = [
        0x3, 0xf, 0x8, 0x4, 0xd, 0x5, 0xb, 0x5, 0xb, 0x5, 0x4, 0x7, 0x0, 0x9, 0x1, 0x7,
    ];
    assert_eq!(u_dec, u64_to_vec_u4(u));
    assert_eq!(u, vec_u4_to_u64(u_dec));

    let u: u64 = 0x0ac6f9cd6e6f275d;
    let u_dec: [u8; 16] = [
        0x0, 0xa, 0xc, 0x6, 0xf, 0x9, 0xc, 0xd, 0x6, 0xe, 0x6, 0xf, 0x2, 0x7, 0x5, 0xd,
    ];
    assert_eq!(u_dec, u64_to_vec_u4(u));
    assert_eq!(u, vec_u4_to_u64(u_dec));
}

// u64 -> [u2; 32], res[0] = 2 MSB bits of u64
pub const fn u64_to_vec_u2(u: u64) -> [u8; 64 / 2] {
    let mut i: usize = 0;
    let mut v: [u8; 64 / 2] = [0; 64 / 2];

    while i < 64 / 2 {
        // for loop unusable inside const
        v[64 / 2 - i - 1] = ((u >> (2 * i)) & 0x3) as u8;
        i += 1;
    }
    v
}

pub const fn vec_u2_to_u64(v: [u8; 64 / 2]) -> u64 {
    let mut i: usize = 0;
    let mut u: u64 = 0;

    while i < 64 / 2 {
        // for loop unusable inside const
        u += (v[i] as u64) << (62 - 2 * i);
        i += 1;
    }
    u
}

#[test]
fn test_u64_conv_vec_u2() {
    let u: u64 = 0x603cd95fa72a8704;
    #[rustfmt::skip]
    let u_dec: [u8; 32] = [
        0x1, 0x2, 0x0, 0x0, 0x0, 0x3, 0x3, 0x0, 0x3, 0x1, 0x2, 0x1, 0x1, 0x1, 0x3, 0x3,
        0x2, 0x2, 0x1, 0x3, 0x0, 0x2, 0x2, 0x2, 0x2, 0x0, 0x1, 0x3, 0x0, 0x0, 0x1, 0x0];
    assert_eq!(u_dec, u64_to_vec_u2(u));
    assert_eq!(u, vec_u2_to_u64(u_dec));

    let u: u64 = 0xee873b2ec447944d;
    #[rustfmt::skip]
    let u_dec: [u8; 32] = [
        0x3, 0x2, 0x3, 0x2, 0x2, 0x0, 0x1, 0x3, 0x0, 0x3, 0x2, 0x3, 0x0, 0x2, 0x3, 0x2,
        0x3, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x3, 0x2, 0x1, 0x1, 0x0, 0x1, 0x0, 0x3, 0x1];
    assert_eq!(u_dec, u64_to_vec_u2(u));
    assert_eq!(u, vec_u2_to_u64(u_dec));
}
