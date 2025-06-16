/// Scalar generation using the hash random oracle
use crate::{
    curve_api::{Curve, FieldOps},
    proofs::{
        pke_v2::{compute_crs_params, inf_norm_bound_to_euclidean_squared},
        Sid,
    },
};

use super::{PKEv2DomainSeparators, PublicCommit, PublicParams};

// The scalar used for the proof are generated using sha3 as a random oracle. The inputs of the hash
// that generates a given scalar are reused for the subsequent hashes. We use the typestate pattern
// to propagate the inputs from one hash to the next.

struct RInputs<'a> {
    ds: &'a PKEv2DomainSeparators,
    sid: Sid,
    metadata: &'a [u8],
    x_bytes: Box<[u8]>,
    C_hat_e_bytes: &'a [u8],
    C_e_bytes: &'a [u8],
    C_r_tilde_bytes: &'a [u8],
    D: usize,
    m: usize,
    n: usize,
    k: usize,
    d: usize,
}

pub(super) struct RHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
}

impl<'a> RHash<'a> {
    pub(super) fn new<G: Curve>(
        public: (&'a PublicParams<G>, &PublicCommit<G>),
        metadata: &'a [u8],
        C_hat_e_bytes: &'a [u8],
        C_e_bytes: &'a [u8],
        C_r_tilde_bytes: &'a [u8],
    ) -> (Box<[i8]>, Self) {
        let (
            &PublicParams {
                g_lists: _,
                D: _,
                n,
                d,
                k: _,
                B_bound_squared: _,
                B_inf,
                q,
                t: t_input,
                msbs_zero_padding_bit_count,
                bound_type,
                sid,
                domain_separators: ref ds,
            },
            PublicCommit { a, b, c1, c2, .. },
        ) = public;

        let k = c2.len();
        let B_squared = inf_norm_bound_to_euclidean_squared(B_inf, d + k);
        let (_, D, _, m) = compute_crs_params(
            d,
            k,
            B_squared,
            t_input,
            msbs_zero_padding_bit_count,
            bound_type,
        );

        let x_bytes = [
            q.to_le_bytes().as_slice(),
            (d as u64).to_le_bytes().as_slice(),
            B_squared.to_le_bytes().as_slice(),
            t_input.to_le_bytes().as_slice(),
            msbs_zero_padding_bit_count.to_le_bytes().as_slice(),
            &*a.iter()
                .flat_map(|&x| x.to_le_bytes())
                .collect::<Box<[_]>>(),
            &*b.iter()
                .flat_map(|&x| x.to_le_bytes())
                .collect::<Box<[_]>>(),
            &*c1.iter()
                .flat_map(|&x| x.to_le_bytes())
                .collect::<Box<[_]>>(),
            &*c2.iter()
                .flat_map(|&x| x.to_le_bytes())
                .collect::<Box<[_]>>(),
        ]
        .iter()
        .copied()
        .flatten()
        .copied()
        .collect::<Box<[_]>>();

        // make R_bar a random number generator from the given bytes
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut hasher = sha3::Shake256::default();
        for &data in &[
            ds.hash_R(),
            sid.to_le_bytes().as_slice(),
            metadata,
            &x_bytes,
            C_hat_e_bytes,
            C_e_bytes,
            C_r_tilde_bytes,
        ] {
            hasher.update(data);
        }
        let mut R_bar = hasher.finalize_xof();
        let R = (0..128 * (2 * (d + k) + 4))
            .map(|_| {
                let mut byte = 0u8;
                R_bar.read(core::slice::from_mut(&mut byte));

                // take two bits
                match byte & 0b11 {
                    // probability 1/2
                    0 | 1 => 0,
                    // probability 1/4
                    2 => 1,
                    // probability 1/4
                    3 => -1,
                    _ => unreachable!(),
                }
            })
            .collect::<Box<[i8]>>();

        let R_coeffs = |i: usize, j: usize| R[i + j * 128];
        let R_bytes = (0..128)
            .flat_map(|i| (0..(2 * (d + k) + 4)).map(move |j| R_coeffs(i, j) as u8))
            .collect();

        (
            R,
            Self {
                R_inputs: RInputs {
                    ds,
                    sid,
                    metadata,
                    x_bytes,
                    C_hat_e_bytes,
                    C_e_bytes,
                    C_r_tilde_bytes,
                    D,
                    m,
                    n,
                    k,
                    d,
                },

                R_bytes,
            },
        )
    }

    pub(super) fn gen_phi<Zp: FieldOps>(self, C_R_bytes: &'a [u8]) -> ([Zp; 128], PhiHash<'a>) {
        let Self { R_inputs, R_bytes } = self;

        let mut phi = [Zp::ZERO; 128];
        Zp::hash(
            &mut phi,
            &[
                R_inputs.ds.hash_phi(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &R_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                C_R_bytes,
                R_inputs.C_r_tilde_bytes,
            ],
        );
        let phi_bytes = phi
            .iter()
            .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
            .collect::<Box<[_]>>();

        (
            phi,
            PhiHash {
                R_inputs,
                phi_inputs: PhiInputs { C_R_bytes },
                R_bytes,
                phi_bytes,
            },
        )
    }
}

struct PhiInputs<'a> {
    C_R_bytes: &'a [u8],
}

pub(super) struct PhiHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
}

impl<'a> PhiHash<'a> {
    pub(super) fn gen_xi<Zp: FieldOps>(self, C_hat_bin_bytes: &'a [u8]) -> ([Zp; 128], XiHash<'a>) {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
        } = self;

        let mut xi = [Zp::ZERO; 128];
        Zp::hash(
            &mut xi,
            &[
                R_inputs.ds.hash_xi(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &R_bytes,
                &phi_bytes,
                phi_inputs.C_R_bytes,
                C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
            ],
        );

        let xi_bytes = xi
            .iter()
            .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
            .collect::<Box<[_]>>();

        (
            xi,
            XiHash {
                R_inputs,
                R_bytes,
                phi_inputs,
                phi_bytes,
                xi_inputs: XiInputs { C_hat_bin_bytes },
                xi_bytes,
            },
        )
    }
}

struct XiInputs<'a> {
    C_hat_bin_bytes: &'a [u8],
}

pub(super) struct XiHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
}

impl<'a> XiHash<'a> {
    pub(super) fn gen_y<Zp: FieldOps>(self) -> (Vec<Zp>, YHash<'a>) {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
        } = self;

        let mut y = vec![Zp::ZERO; R_inputs.D + 128 * R_inputs.m];
        Zp::hash(
            &mut y,
            &[
                R_inputs.ds.hash(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &R_bytes,
                &phi_bytes,
                &xi_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
            ],
        );
        let y_bytes = y
            .iter()
            .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
            .collect::<Box<[_]>>();

        (
            y,
            YHash {
                R_inputs,
                R_bytes,
                phi_inputs,
                phi_bytes,
                xi_inputs,
                xi_bytes,
                y_bytes,
            },
        )
    }
}

pub(super) struct YHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
}

impl<'a> YHash<'a> {
    pub(super) fn gen_t<Zp: FieldOps>(self, C_y_bytes: &'a [u8]) -> (Vec<Zp>, THash<'a>) {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
        } = self;

        let mut t = vec![Zp::ZERO; R_inputs.n];
        Zp::hash_128bit(
            &mut t,
            &[
                R_inputs.ds.hash_t(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &y_bytes,
                &phi_bytes,
                &xi_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                C_y_bytes,
            ],
        );
        let t_bytes = t
            .iter()
            .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
            .collect::<Box<[_]>>();

        (
            t,
            THash {
                R_inputs,
                R_bytes,
                phi_inputs,
                phi_bytes,
                xi_inputs,
                xi_bytes,
                y_bytes,
                t_inputs: TInputs { C_y_bytes },
                t_bytes,
            },
        )
    }
}

struct TInputs<'a> {
    C_y_bytes: &'a [u8],
}

pub(super) struct THash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
}

impl<'a> THash<'a> {
    pub(super) fn gen_theta<Zp: FieldOps>(self) -> (Vec<Zp>, ThetaHash<'a>) {
        let Self {
            R_inputs,
            phi_inputs,
            xi_inputs,
            t_inputs,
            t_bytes,
            R_bytes,
            phi_bytes,
            xi_bytes,
            y_bytes,
        } = self;

        let mut theta = vec![Zp::ZERO; R_inputs.d + R_inputs.k];
        Zp::hash(
            &mut theta,
            &[
                R_inputs.ds.hash_lmap(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &y_bytes,
                &t_bytes,
                &phi_bytes,
                &xi_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
        );
        let theta_bytes = theta
            .iter()
            .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
            .collect::<Box<[_]>>();

        (
            theta,
            ThetaHash {
                R_inputs,
                R_bytes,
                phi_inputs,
                phi_bytes,
                xi_inputs,
                xi_bytes,
                y_bytes,
                t_inputs,
                t_bytes,
                theta_bytes,
            },
        )
    }
}

pub(super) struct ThetaHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
}

impl<'a> ThetaHash<'a> {
    pub(super) fn gen_omega<Zp: FieldOps>(self) -> (Vec<Zp>, OmegaHash<'a>) {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
            t_inputs,
            t_bytes,
            theta_bytes,
        } = self;

        let mut omega = vec![Zp::ZERO; R_inputs.n];
        Zp::hash_128bit(
            &mut omega,
            &[
                R_inputs.ds.hash_w(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &y_bytes,
                &t_bytes,
                &phi_bytes,
                &xi_bytes,
                &theta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
        );
        let omega_bytes = omega
            .iter()
            .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
            .collect::<Box<[_]>>();

        (
            omega,
            OmegaHash {
                R_inputs,
                R_bytes,
                phi_inputs,
                phi_bytes,
                xi_inputs,
                xi_bytes,
                y_bytes,
                t_inputs,
                t_bytes,
                theta_bytes,
                omega_bytes,
            },
        )
    }
}

pub(super) struct OmegaHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
    omega_bytes: Box<[u8]>,
}

impl<'a> OmegaHash<'a> {
    pub(super) fn gen_delta<Zp: FieldOps>(self) -> ([Zp; 7], DeltaHash<'a>) {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
            t_inputs,
            t_bytes,
            theta_bytes,
            omega_bytes,
        } = self;

        let mut delta = [Zp::ZERO; 7];
        Zp::hash(
            &mut delta,
            &[
                R_inputs.ds.hash_agg(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &y_bytes,
                &t_bytes,
                &phi_bytes,
                &xi_bytes,
                &theta_bytes,
                &omega_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
        );
        let delta_bytes = delta
            .iter()
            .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
            .collect::<Box<[_]>>();

        (
            delta,
            DeltaHash {
                R_inputs,
                R_bytes,
                phi_inputs,
                phi_bytes,
                xi_inputs,
                xi_bytes,
                y_bytes,
                t_inputs,
                t_bytes,
                theta_bytes,
                delta_bytes,
            },
        )
    }
}

pub(super) struct DeltaHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
    delta_bytes: Box<[u8]>,
}

impl<'a> DeltaHash<'a> {
    pub(super) fn gen_z<Zp: FieldOps>(
        self,
        C_h1_bytes: &'a [u8],
        C_h2_bytes: &'a [u8],
        C_hat_t_bytes: &'a [u8],
        C_hat_h3_bytes: &'a [u8],
        C_hat_w_bytes: &'a [u8],
    ) -> (Zp, ZHash<'a, Zp>) {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
            t_inputs,
            t_bytes,
            theta_bytes,
            delta_bytes,
        } = self;

        let mut z = Zp::ZERO;
        Zp::hash(
            core::slice::from_mut(&mut z),
            &[
                R_inputs.ds.hash_z(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &y_bytes,
                &t_bytes,
                &phi_bytes,
                &R_inputs.x_bytes, // x is duplicated but we have to keep it for backward compat
                &theta_bytes,
                &delta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
                C_h1_bytes,
                C_h2_bytes,
                C_hat_t_bytes,
                C_hat_h3_bytes,
                C_hat_w_bytes,
            ],
        );

        (
            z,
            ZHash {
                R_inputs,
                R_bytes,
                phi_inputs,
                phi_bytes,
                xi_inputs,
                xi_bytes,
                y_bytes,
                t_inputs,
                t_bytes,
                theta_bytes,
                delta_bytes,
                z_inputs: ZInputs {
                    C_h1_bytes,
                    C_h2_bytes,
                    C_hat_t_bytes,
                    C_hat_h3_bytes,
                    C_hat_w_bytes,
                },
                z,
            },
        )
    }
}

struct ZInputs<'a> {
    C_h1_bytes: &'a [u8],
    C_h2_bytes: &'a [u8],
    C_hat_t_bytes: &'a [u8],
    C_hat_h3_bytes: &'a [u8],
    C_hat_w_bytes: &'a [u8],
}

pub(super) struct ZHash<'a, Zp: FieldOps> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
    delta_bytes: Box<[u8]>,
    z_inputs: ZInputs<'a>,
    z: Zp,
}

impl<'a, Zp: FieldOps> ZHash<'a, Zp> {
    pub(super) fn gen_chi(self, p_h1: Zp, p_h2: Zp, p_t: Zp) -> Zp {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
            t_inputs,
            t_bytes,
            theta_bytes,
            delta_bytes,
            z_inputs,
            z,
        } = self;

        let mut chi = Zp::ZERO;
        Zp::hash(
            core::slice::from_mut(&mut chi),
            &[
                R_inputs.ds.hash_chi(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &y_bytes,
                &t_bytes,
                &phi_bytes,
                &xi_bytes,
                &theta_bytes,
                &delta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
                z_inputs.C_h1_bytes,
                z_inputs.C_h2_bytes,
                z_inputs.C_hat_t_bytes,
                z_inputs.C_hat_h3_bytes,
                z_inputs.C_hat_w_bytes,
                z.to_le_bytes().as_ref(),
                p_h1.to_le_bytes().as_ref(),
                p_h2.to_le_bytes().as_ref(),
                p_t.to_le_bytes().as_ref(),
            ],
        );

        chi
    }
}
