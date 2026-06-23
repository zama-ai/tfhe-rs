use rayon::prelude::*;
use tfhe::shortint::prelude::*;

use crate::permute; // permute/shuffle/swap arrays
use crate::pv2_lut; // fhe luts and constants for prince v2

/* Macro to monitor individual functions timings (feature related: "verbose-timings") */
macro_rules! monitor {
    ($fn:ident($( $a:expr ), *)) => {
        #[cfg(feature = "verbose-timings")]
        let t0 = std::time::Instant::now();
        $fn($( $a), *);
        #[cfg(feature = "verbose-timings")]
        eprintln!("{}:\t{:.4?}", stringify!($fn), t0.elapsed())
    }
}

/* out_u4 = (in_u2q xor ct_k) as vec_u4
 * [Parallel:(32)/32/(16)] XOR stage -> u4 */
fn pv2_xor_to_u4(
    ev_key: &ServerKey,
    out_u4: &mut [Ciphertext; 16],
    in_u2q: &[Ciphertext; 32],
    ct_k: &[Ciphertext; 32],
) {
    // xor alternatively to pair of high/low bits
    let zlut_xor_fw = [
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_FW[0][x as usize] as u64),
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_FW[1][x as usize] as u64),
    ];

    /* "Bivariate" xor ------------------------------------------------------------------
     * Sum in_u2q + ct_k, apply xor LUT to high or low bit */
    /* [Sequential]
    let mut ct_hl: [Ciphertext; 32] = std::array::from_fn(|n| ev_key.unchecked_add(&in_u2q[n], &ct_k[n]));
    for n in 0..32 {
        ev_key.apply_lookup_table_assign(&mut ct_hl[n], &zlut_xor_fw[n & 0x1]);
    }
    // */
    //* [Parallel:32]
    let ct_hl: [Ciphertext; 32] = (0..32)
        .into_par_iter()
        .map(|n| {
            let both_n: Ciphertext = ev_key.unchecked_add(&in_u2q[n], &ct_k[n]);
            ev_key.apply_lookup_table(&both_n, &zlut_xor_fw[n & 0x1]) // Combined version faster?
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    // */
    // [Parallel:16] Sum by pairs
    /* (*out_u4) = (0..16).into_par_iter().map(|w| {
        ev_key.unchecked_add(&ct_hl[2*w], &ct_hl[2*w+1])
    }).collect::<Vec<_>>().try_into().unwrap();*/
    for w in 0..16 {
        out_u4[w] = ev_key.unchecked_add(&ct_hl[2 * w], &ct_hl[2 * w + 1]);
    }
}

/* out_b = (in_u2q xor ct_k) as vec_b
 * [Parallel:(32)/64] -> drifted bits */
fn pv2_xor_to_b(
    ev_key: &ServerKey,
    out_b: &mut [Ciphertext; 64],
    in_u2q: &[Ciphertext; 32],
    ct_k: &[Ciphertext; 32],
) {
    let zlut_xor_bh = [
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_BH[0][x as usize] as u64),
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_BH[1][x as usize] as u64),
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_BH[2][x as usize] as u64),
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_BH[3][x as usize] as u64),
    ];
    let zlut_xor_bl = [
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_BL[0][x as usize] as u64),
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_BL[1][x as usize] as u64),
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_BL[2][x as usize] as u64),
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_BL[3][x as usize] as u64),
    ];

    // [Parallel:32] Sum in_u2q + ct_k --> could stay as iter? and assign in the following loop
    let ct_hl: [Ciphertext; 32] =
        std::array::from_fn(|n| ev_key.unchecked_add(&in_u2q[n], &ct_k[n]));

    // Apply xor (incl. bit_extract) luts on each nibble
    /* [Sequential]
    for w in 0..16 {
        let b_pos    = w & 0x3; // w mod 4 (b_pos:0123_b, so b_pos=0 is for (b << 3))
        out_b[4*w]   = ev_key.apply_lookup_table(&ct_hl[2*w],   &zlut_xor_bh[b_pos]);
        out_b[4*w+1] = ev_key.apply_lookup_table(&ct_hl[2*w],   &zlut_xor_bl[b_pos]);
        out_b[4*w+2] = ev_key.apply_lookup_table(&ct_hl[2*w+1], &zlut_xor_bh[b_pos]);
        out_b[4*w+3] = ev_key.apply_lookup_table(&ct_hl[2*w+1], &zlut_xor_bl[b_pos]);
    } // */
    //* [Parallel:64] Apply xor (incl. bit_extract) luts on each nibble
    (*out_b) = (0..64)
        .into_par_iter()
        .map(|idx| {
            let n: usize = idx >> 1; // 2*w or 2*w+1
            let w: usize = idx >> 2;
            let b_pos: usize = w & 0x3;
            let zlut_bhl_pos = if (idx & 0x1) == 1 {
                &zlut_xor_bl[b_pos]
            } else {
                &zlut_xor_bh[b_pos]
            };
            ev_key.apply_lookup_table(&ct_hl[n], zlut_bhl_pos)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap(); // */
}

// [Parallel:(32)/32]
fn pv2_xor_to_u2(
    ev_key: &ServerKey,
    out_u2: &mut [Ciphertext; 32],
    in_u2q: &[Ciphertext; 32],
    ct_k: &[Ciphertext; 32],
) {
    let zlut_xor =
        ev_key.generate_lookup_table(|x: u64| pv2_lut::PV2_XOR_TO_LOW[x as usize] as u64);

    /* [Sequential]
    for n in 0..32 {
        out_u2[n] = ev_key.unchecked_add(&in_u2q[n], &ct_k[n]);
        ev_key.apply_lookup_table_assign(&mut out_u2[n], &zlut_xor);
    } // */
    // [Parallel:32] Apply xor luts on each nibble
    //* [Parallel:32]
    (*out_u2) = (0..32)
        .into_par_iter()
        .map(|n| {
            let both_n: Ciphertext = ev_key.unchecked_add(&in_u2q[n], &ct_k[n]);
            ev_key.apply_lookup_table(&both_n, &zlut_xor)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap(); // */
}

// [Parallel:64/(32/16)/64/(32)] Fw Round
// Forward round receives full 4-bit nibbles (16) and returns 2-bit nibbles (32) packed on high bits
fn pv2_fw_round(
    ev_key: &ServerKey,
    out_u2q: &mut [Ciphertext; 32], // out: 2-bits (high)
    in_u4: &[Ciphertext; 16],       // in:  4-bits (full)
    zlut: &[[u8; 16]; 16],
) {
    /* S-Boxes ------------------------------------------------------------------------------------
     * . each 4-bit nibbles requires 4 applications of (same LUT + Bit extraction)
     * . extracted bits for word w go at position 3-w mod 4 (w=0 --> b000, w=1 --> 0b00, etc) */
    /* [Sequential]
    let mut ct_tmp: [Ciphertext; 64] = std::array::from_fn(|_| ev_key.create_trivial(0));
    for w in 0..16 {
        for b in 0..4 { // use apply_many_lookup_tables ?
            let zlut_b = ev_key.generate_lookup_table(
                |x:u64| (((zlut[w][x as usize] >> (3-b)) & 0x1) << ((3-w) % 4)) as u64
            );
            ct_tmp[b + 4*w] = ev_key.apply_lookup_table(&in_u4[w], &zlut_b);
        }
    } // */
    /* [Sequential::array]
    let mut ct_tmp: [Ciphertext; 64] = std::array::from_fn(|idx| {
        let w: usize = idx >> 2;
        let b: usize = idx & 0x3;
        let zlut_b = ev_key.generate_lookup_table(
            |x:u64| (((zlut[w][x as usize] >> (3-b)) & 0x1) << ((3-w) % 4)) as u64
        );
        ev_key.apply_lookup_table(&in_u4[w], &zlut_b) // ct_tmp[idx]
    }); // */
    //* [Parallel:64]
    let ct_tmp: [Ciphertext; 64] = (0..64)
        .into_par_iter()
        .map(|idx| {
            // idx = 4*w + b
            let w: usize = idx >> 2;
            let b: usize = idx & 0x3;
            let zlut_b = ev_key.generate_lookup_table(|x: u64| {
                // [Nb] w=0..15
                (((zlut[w][x as usize] >> (3 - b)) & 0x1) << (3 - (w % 4))) as u64
            });
            ev_key.apply_lookup_table(&in_u4[w], &zlut_b)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    // */
    /* Bridging Sbox --> MLayer ----------------------------------------------------------
     * So as to obtain 4-bit enc nibbles with: 048c, 159d, etc */
    // TODO(?): [Parallel:32/16]
    for w in 0..16 {
        // this uses u2q for some u4 ahead of time (as temporary holder)
        let oo: usize = 16 * (w / 4) + (w % 4);
        out_u2q[w] = ev_key.unchecked_add(&ct_tmp[oo], &ct_tmp[oo + 4]);
        out_u2q[w + 1] = ev_key.unchecked_add(&ct_tmp[oo + 8], &ct_tmp[oo + 12]);
        out_u2q[w] = ev_key.unchecked_add(&out_u2q[w], &out_u2q[w + 1]);
    }

    /* M-layer: Apply exor matrices ------------------------------------------------------ */
    /* [Sequential]
    for w in 0..16 {
        for b in 0..4 {
            let zlut_ex = ev_key.generate_lookup_table(
                |x:u64| pv2_lut::PV2_EXOR_FW[w % 2][b][x as usize] as u64
            );
            ct_tmp[b + 4*w] = ev_key.apply_lookup_table(&out_u2q[w], &zlut_ex);
        }
    } // */
    //* [Parallel:64]
    let mut ct_tmp: [Ciphertext; 64] = (0..64)
        .into_par_iter()
        .map(|idx| {
            // idx = 4*w + b
            let w: usize = idx >> 2;
            let b: usize = idx & 0x3;
            let zlut_ex = ev_key
                .generate_lookup_table(|x: u64| pv2_lut::PV2_EXOR_FW[w % 2][b][x as usize] as u64);
            ev_key.apply_lookup_table(&out_u2q[w], &zlut_ex)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap(); // */
                   // Apply Fhe Perm permutation + Permutation Layer
                   // --> Directly assign correctly in above loop? as ct_tmp[INV_FHE_MP_PERM_FW[b + 4*w]] = ...
    permute::apply_perm_assign(&mut ct_tmp, &pv2_lut::FHE_MP_PERM_FW);

    /* Bridging M-Layer --> Xor --------------------------------------------------------- */
    // [Parallel:32] Combine pairs
    for n in 0..32 {
        out_u2q[n] = ev_key.unchecked_add(&ct_tmp[2 * n], &ct_tmp[2 * n + 1]);
    }
}

// [Parallel:64/(32)/64/(32/16)/64/(32)/32/(32/16)/32]
fn pv2_mid_round(
    ev_key: &ServerKey,
    out_u2q: &mut [Ciphertext; 32], // out: 2-bits (high)
    in_u4: &[Ciphertext; 16],       // in:  4-bits (full)
    ct_k_fst: &[Ciphertext; 32],
    ct_k_scd: &[Ciphertext; 32],
    zlut_fst: &[[u8; 16]; 16],
    zlut_scd: &[[u8; 16]; 16],
) {
    /* S-Boxes ------------------------------------------------------------------------------------
     * /!\ output for xor */
    /* [Sequential]
    for w in 0..16 {
        for b in 0..2 {
            let zlut_u2q = ev_key.generate_lookup_table(
                |x:u64| (((pv2_lut::PV2_5_S_M[w][x as usize] >> (2-2*b)) & 0x3) << 2) as u64
            );
            out_u2q[b + 2*w] = ev_key.apply_lookup_table(&in_u4[w], &zlut_u2q);
        }
    } // */
    //* [Parallel:64]
    (*out_u2q) = (0..32)
        .into_par_iter()
        .map(|n| {
            let w: usize = n >> 1;
            let b: usize = n & 0x1;
            let zlut_u2q = ev_key.generate_lookup_table(|x: u64| {
                (((zlut_fst[w][x as usize] >> (2 - 2 * b)) & 0x3) << 2) as u64
            });
            ev_key.apply_lookup_table(&in_u4[w], &zlut_u2q)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap(); // */
                   /* XOR K0 [Parallel:(32)/64] --------------------------------------------------------- */
    let mut ct_tmp_b: [Ciphertext; 64] = std::array::from_fn(|_| ev_key.create_trivial(0));
    pv2_xor_to_b(ev_key, &mut ct_tmp_b, out_u2q, ct_k_fst);

    /* Bridging to M-Layer --------------------------------------------------------------- */
    // [Parallel:32/16] Comb sum (048c,...)
    let mut ct_tmp_u4: [Ciphertext; 16] = std::array::from_fn(|_| ev_key.create_trivial(0));
    for w in 0..16 {
        // mm, use u2q for some u4 ahead of time
        let oo: usize = 16 * (w / 4) + (w % 4);
        out_u2q[w] = ev_key.unchecked_add(&ct_tmp_b[oo], &ct_tmp_b[oo + 4]);
        out_u2q[w + 1] = ev_key.unchecked_add(&ct_tmp_b[oo + 8], &ct_tmp_b[oo + 12]);
        ct_tmp_u4[w] = ev_key.unchecked_add(&out_u2q[w], &out_u2q[w + 1]);
    }

    /* M-layer: Apply exor matrices ------------------------------------------------------ */
    /* [Sequential]
    for w in 0..16 {
        for b in 0..4 {
            let zlut_ex = ev_key.generate_lookup_table(
                |x:u64| pv2_lut::PV2_EXOR_FW[w % 2][b][x as usize] as u64
            );
            ct_tmp_b[b + 4*w] = ev_key.apply_lookup_table(&ct_tmp_u4[w], &zlut_ex);
        }
    } // */
    //* [Parallel:64]
    ct_tmp_b = (0..64)
        .into_par_iter()
        .map(|idx| {
            // idx = 4*w + b
            let w: usize = idx >> 2;
            let b: usize = idx & 0x3;
            let zlut_ex = ev_key
                .generate_lookup_table(|x: u64| pv2_lut::PV2_EXOR_FW[w % 2][b][x as usize] as u64);
            ev_key.apply_lookup_table(&ct_tmp_u4[w], &zlut_ex)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    // */
    // Apply Fhe Perm permutation
    permute::apply_perm_assign(&mut ct_tmp_b, &pv2_lut::FHE_M_PERM);

    /* Bridging M-Layer --> Xor --------------------------------------------------------- */
    // [Parallel:32] Combine pairs
    for n in 0..32 {
        out_u2q[n] = ev_key.unchecked_add(&ct_tmp_b[2 * n], &ct_tmp_b[2 * n + 1]);
    }

    /* XOR k1 [Parallel:(32)/32/(16)] --------------------------------------------------- */
    pv2_xor_to_u4(ev_key, &mut ct_tmp_u4, out_u2q, ct_k_scd);

    /* S-Boxes ------------------------------------------------------------------------------------
     * . output 2,2 bits on position (32)00 */
    /* [Sequential]
    for w in 0..16 {
        for b in 0..2 {
            let zlut_u2q = ev_key.generate_lookup_table(
                |x:u64| (((pv2_lut::PV2_0_IS_0[w][x as usize] >> (2-2*b)) & 0x3) << 2) as u64
            );
            out_u2q[b + 2*w] = ev_key.apply_lookup_table(&ct_tmp_u4[w], &zlut_u2q);
        }
    }
    // */
    //* [Parallel:32]
    (*out_u2q) = (0..32)
        .into_par_iter()
        .map(|n| {
            let w: usize = n >> 1;
            let b: usize = n & 0x1;
            let zlut_u2q = ev_key.generate_lookup_table(|x: u64| {
                (((zlut_scd[w][x as usize] >> (2 - 2 * b)) & 0x3) << 2) as u64
            });
            ev_key.apply_lookup_table(&ct_tmp_u4[w], &zlut_u2q)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap(); // */
}

// [Parallel:(32/16)/64/(32/16)/32]
fn pv2_bw_round(
    ev_key: &ServerKey,
    out_u2q: &mut [Ciphertext; 32], // out: 2-bits (high)
    in_b: &[Ciphertext; 64],        // in:  1-bits (<< w%4 = 333322221111000033...)
    zlut: &[[u8; 16]; 16],
) {
    let mut ct_tmp_u4: [Ciphertext; 16] = std::array::from_fn(|_| ev_key.create_trivial(0)); // ...

    // iPerm + M-Layer
    // [Parallel:32/16] Combined iPerm + comb sum (048c,etc)
    for w in 0..16 {
        let idx: [usize; 4] =
            std::array::from_fn(|b| (w & 0x3) + 4 * pv2_lut::IPERM[4 * (w >> 2) + b]);
        out_u2q[2 * w] = ev_key.unchecked_add(&in_b[idx[0]], &in_b[idx[1]]);
        out_u2q[2 * w + 1] = ev_key.unchecked_add(&in_b[idx[2]], &in_b[idx[3]]);
        ct_tmp_u4[w] = ev_key.unchecked_add(&out_u2q[2 * w], &out_u2q[2 * w + 1]);
    }

    /* M-layer: Apply exor matrices ------------------------------------------------------ */
    /* [Sequential]
    let mut ct_tmp_b:  [Ciphertext; 64] = std::array::from_fn(|_| ev_key.create_trivial(0));
    for w in 0..16 {
        for b in 0..4 {
            let zlut_ex = ev_key.generate_lookup_table(
                |x:u64| pv2_lut::PV2_EXOR_BW[w % 4][b][x as usize] as u64
            );
            ct_tmp_b[b + 4*w] = ev_key.apply_lookup_table(&ct_tmp_u4[w], &zlut_ex);
        }
    } // */
    //* [Parallel:64]
    let mut ct_tmp_b: [Ciphertext; 64] = (0..64)
        .into_par_iter()
        .map(|idx| {
            // idx = 4*w + b
            let w: usize = idx >> 2;
            let b: usize = idx & 0x3;
            let zlut_ex = ev_key
                .generate_lookup_table(|x: u64| pv2_lut::PV2_EXOR_BW[w % 4][b][x as usize] as u64);
            ev_key.apply_lookup_table(&ct_tmp_u4[w], &zlut_ex)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    // */
    // FHE Perm permutation
    permute::apply_perm_assign(&mut ct_tmp_b, &pv2_lut::FHE_M_PERM);

    /* Bridging MLayer --> SBox ----------------------------------------------------------- */
    // [Parallel:32/16] Combine to u4 = sum[4*i:4*i+4] for i in range(16)
    for w in 0..16 {
        out_u2q[2 * w] = ev_key.unchecked_add(&ct_tmp_b[4 * w], &ct_tmp_b[4 * w + 1]);
        out_u2q[2 * w + 1] = ev_key.unchecked_add(&ct_tmp_b[4 * w + 2], &ct_tmp_b[4 * w + 3]);
        ct_tmp_u4[w] = ev_key.unchecked_add(&out_u2q[2 * w], &out_u2q[2 * w + 1]);
    }

    /* S-Boxes ------------------------------------------------------------------------------------
     * . output 2,2 bits on position (32)00 */
    /* [Sequential]
    for w in 0..16 {
        for b in 0..2 {
            let zlut_u2q = ev_key.generate_lookup_table(
                |x:u64| (((zlut[w][x as usize] >> (2-2*b)) & 0x3) << 2) as u64
            );
            out_u2q[b + 2*w] = ev_key.apply_lookup_table(&ct_tmp_u4[w], &zlut_u2q);
        }
    }
    // */
    //* [Parallel:32]
    (*out_u2q) = (0..32)
        .into_par_iter()
        .map(|n| {
            let w: usize = n >> 1;
            let b: usize = n & 0x1;
            let zlut_u2q = ev_key.generate_lookup_table(|x: u64| {
                (((zlut[w][x as usize] >> (2 - 2 * b)) & 0x3) << 2) as u64
            });
            ev_key.apply_lookup_table(&ct_tmp_u4[w], &zlut_u2q)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap(); // */
}

/* Encryption -----------------------------------------------------------------------------------
 * (Whitening + Fw Rounds + Mid Round + Bw Rounds + Whitening)
 */

#[rustfmt::skip] // [skip] Each of 22 monitor! calls get split on 5 lines which destroys readability
pub fn pv2_encrypt(
    ev_key: &ServerKey,
    ct_enc: &mut [Ciphertext; 32],
    ct_m: &[Ciphertext; 32],
    ct_k0: &[Ciphertext; 32],
    ct_k1: &[Ciphertext; 32],
) {
    // Work buffers: u4, u2q, b (depending on the inner nibbles format, u2q = u2 <<2)
    let mut ct_u4: [Ciphertext; 16] = std::array::from_fn(|_| ev_key.create_trivial(0));
    let mut ct_b: [Ciphertext; 64] = std::array::from_fn(|_| ev_key.create_trivial(0));
    // [Parallel] + Init: ct_m << 2
    let mut ct_u2q: [Ciphertext; 32] =
        std::array::from_fn(|n| ev_key.unchecked_scalar_mul(&ct_m[n], 4));

    // Whitening
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k0));
    // Forward rounds
    //*
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_0_S_0));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k1));
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_1_S_2));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k0));
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_0_S_0));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k1));
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_3_S_4));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k0));
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_0_S_0));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k1)); // */
    // Middle round
    //*
    monitor!(pv2_mid_round(ev_key, &mut ct_u2q, &ct_u4,
                           ct_k0, ct_k1, &pv2_lut::PV2_5_S_M, &pv2_lut::PV2_0_IS_0)); // */
    // Backward rounds
    //*
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k0));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_6_IS_7));
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k1));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_0_IS_0));
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k0));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_8_IS_9));
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k1));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_0_IS_0));
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k0));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_A_IS_B));
    // Last Xor to u2l
    monitor!(pv2_xor_to_u2(ev_key, ct_enc, &ct_u2q, ct_k1)); // */
}

/* Decryption -----------------------------------------------------------------------------------
 * Inverse of pv2_encrypt().
 */

#[rustfmt::skip] // [skip] Each of 22 monitor! calls get split on 5 lines which destroys readability
pub fn pv2_decrypt(
    ev_key: &ServerKey,
    ct_dec: &mut [Ciphertext; 32],
    ct_c: &[Ciphertext; 32],
    ct_k0: &[Ciphertext; 32],
    ct_k1: &[Ciphertext; 32],
) {
    // Work buffers: u4, u2q, b (depending on the inner nibbles format, u2q = u2 <<2)
    let mut ct_u4: [Ciphertext; 16] = std::array::from_fn(|_| ev_key.create_trivial(0));
    let mut ct_b: [Ciphertext; 64] = std::array::from_fn(|_| ev_key.create_trivial(0));
    // [Parallel] + Init: ct_m << 2
    let mut ct_u2q: [Ciphertext; 32] =
        std::array::from_fn(|n| ev_key.unchecked_scalar_mul(&ct_c[n], 4));

    // Whitening
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k1));
    // Forward rounds
    //*
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_B_S_A));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k0));
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_0_S_0));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k1));
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_9_S_8));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k0));
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_0_S_0));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k1));
    monitor!(pv2_fw_round(ev_key, &mut ct_u2q, &ct_u4, &pv2_lut::PV2_7_S_6));
    monitor!(pv2_xor_to_u4(ev_key, &mut ct_u4, &ct_u2q, ct_k0)); // */
    // Middle round
    //*
    monitor!(pv2_mid_round(ev_key, &mut ct_u2q, &ct_u4,
                           ct_k1, ct_k0, &pv2_lut::PV2_0_S_0, &pv2_lut::PV2_M_IS_5)); // */
    // Backward rounds
    //*
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k1));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_0_IS_0));
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k0));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_4_IS_3));
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k1));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_0_IS_0));
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k0));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_2_IS_1));
    monitor!(pv2_xor_to_b(ev_key, &mut ct_b, &ct_u2q, ct_k1));
    monitor!(pv2_bw_round(ev_key, &mut ct_u2q, &ct_b, &pv2_lut::PV2_0_IS_0));
    // Last Xor to u2l
    monitor!(pv2_xor_to_u2(ev_key, ct_dec, &ct_u2q, ct_k0)); // */
}
