/// Scalar generation using the hash random oracle
use crate::{
    curve_api::{Curve, CurveGroupOps, FieldOps},
    proofs::{
        pke_v2::{compute_crs_params, inf_norm_bound_to_euclidean_squared},
        Sid,
    },
};

use super::{ComputeLoadProofFields, PKEv2DomainSeparators, PublicCommit, PublicParams};

// The scalar used for the proof are generated using sha3 as a random oracle. The inputs of the hash
// that generates a given scalar are reused for the subsequent hashes. We use the typestate pattern
// to propagate the inputs from one hash to the next.

struct RInputs<'a, G: Curve> {
    ds: &'a PKEv2DomainSeparators,
    sid: Sid,
    metadata: &'a [u8],
    x_bytes: Box<[u8]>,
    C_hat_e: G::G2,
    C_e: G::G1,
    C_r_tilde: G::G1,
    D: usize,
    m: usize,
    n: usize,
    k: usize,
    d: usize,
}

pub(super) struct RHash<'a, G: Curve> {
    R_inputs: RInputs<'a, G>,
    R_bytes: Box<[u8]>,
}

impl<'a, G: Curve> RHash<'a, G> {
    pub(super) fn new(
        public: (&'a PublicParams<G>, &PublicCommit<G>),
        metadata: &'a [u8],
        C_hat_e: G::G2,
        C_e: G::G1,
        C_r_tilde: G::G1,
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
            C_hat_e.to_le_bytes().as_ref(),
            C_e.to_le_bytes().as_ref(),
            C_r_tilde.to_le_bytes().as_ref(),
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
                    C_hat_e,
                    C_e,
                    C_r_tilde,
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

    pub(super) fn gen_phi(self, C_R: G::G1) -> ([G::Zp; 128], PhiHash<'a, G>) {
        let Self { R_inputs, R_bytes } = self;

        let mut phi = [G::Zp::ZERO; 128];
        G::Zp::hash(
            &mut phi,
            &[
                R_inputs.ds.hash_phi(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &R_bytes,
                R_inputs.C_hat_e.to_le_bytes().as_ref(),
                R_inputs.C_e.to_le_bytes().as_ref(),
                C_R.to_le_bytes().as_ref(),
                R_inputs.C_r_tilde.to_le_bytes().as_ref(),
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
                phi_inputs: PhiInputs { C_R },
                R_bytes,
                phi_bytes,
            },
        )
    }
}

struct PhiInputs<G: Curve> {
    C_R: G::G1,
}

pub(super) struct PhiHash<'a, G: Curve> {
    R_inputs: RInputs<'a, G>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<G>,
    phi_bytes: Box<[u8]>,
}

impl<'a, G: Curve> PhiHash<'a, G> {
    pub(super) fn gen_xi(self, C_hat_bin: G::G2) -> ([G::Zp; 128], XiHash<'a, G>) {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
        } = self;

        let mut xi = [G::Zp::ZERO; 128];
        G::Zp::hash(
            &mut xi,
            &[
                R_inputs.ds.hash_xi(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                R_inputs.C_hat_e.to_le_bytes().as_ref(),
                R_inputs.C_e.to_le_bytes().as_ref(),
                &R_bytes,
                &phi_bytes,
                phi_inputs.C_R.to_le_bytes().as_ref(),
                C_hat_bin.to_le_bytes().as_ref(),
                R_inputs.C_r_tilde.to_le_bytes().as_ref(),
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
                xi_inputs: XiInputs { C_hat_bin },
                xi_bytes,
            },
        )
    }
}

struct XiInputs<G: Curve> {
    C_hat_bin: G::G2,
}

pub(super) struct XiHash<'a, G: Curve> {
    R_inputs: RInputs<'a, G>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<G>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<G>,
    xi_bytes: Box<[u8]>,
}

impl<'a, G: Curve> XiHash<'a, G> {
    pub(super) fn gen_y(self) -> (Vec<G::Zp>, YHash<'a, G>) {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
        } = self;

        let mut y = vec![G::Zp::ZERO; R_inputs.D + 128 * R_inputs.m];
        G::Zp::hash(
            &mut y,
            &[
                R_inputs.ds.hash(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &R_bytes,
                &phi_bytes,
                &xi_bytes,
                R_inputs.C_hat_e.to_le_bytes().as_ref(),
                R_inputs.C_e.to_le_bytes().as_ref(),
                phi_inputs.C_R.to_le_bytes().as_ref(),
                xi_inputs.C_hat_bin.to_le_bytes().as_ref(),
                R_inputs.C_r_tilde.to_le_bytes().as_ref(),
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

pub(super) struct YHash<'a, G: Curve> {
    R_inputs: RInputs<'a, G>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<G>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<G>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
}

impl<'a, G: Curve> YHash<'a, G> {
    pub(super) fn gen_t(self, C_y: G::G1) -> (Vec<G::Zp>, THash<'a, G>) {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
        } = self;

        let mut t = vec![G::Zp::ZERO; R_inputs.n];
        G::Zp::hash_128bit(
            &mut t,
            &[
                R_inputs.ds.hash_t(),
                R_inputs.sid.to_le_bytes().as_slice(),
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &y_bytes,
                &phi_bytes,
                &xi_bytes,
                R_inputs.C_hat_e.to_le_bytes().as_ref(),
                R_inputs.C_e.to_le_bytes().as_ref(),
                &R_bytes,
                phi_inputs.C_R.to_le_bytes().as_ref(),
                xi_inputs.C_hat_bin.to_le_bytes().as_ref(),
                R_inputs.C_r_tilde.to_le_bytes().as_ref(),
                C_y.to_le_bytes().as_ref(),
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
                t_inputs: TInputs { C_y },
                t_bytes,
            },
        )
    }
}

struct TInputs<G: Curve> {
    C_y: G::G1,
}

pub(super) struct THash<'a, G: Curve> {
    R_inputs: RInputs<'a, G>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<G>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<G>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<G>,
    t_bytes: Box<[u8]>,
}

impl<'a, G: Curve> THash<'a, G> {
    pub(super) fn gen_theta(self) -> (Vec<G::Zp>, ThetaHash<'a, G>) {
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

        let mut theta = vec![G::Zp::ZERO; R_inputs.d + R_inputs.k];
        G::Zp::hash(
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
                R_inputs.C_hat_e.to_le_bytes().as_ref(),
                R_inputs.C_e.to_le_bytes().as_ref(),
                &R_bytes,
                phi_inputs.C_R.to_le_bytes().as_ref(),
                xi_inputs.C_hat_bin.to_le_bytes().as_ref(),
                R_inputs.C_r_tilde.to_le_bytes().as_ref(),
                t_inputs.C_y.to_le_bytes().as_ref(),
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

pub(super) struct ThetaHash<'a, G: Curve> {
    R_inputs: RInputs<'a, G>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<G>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<G>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<G>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
}

impl<'a, G: Curve> ThetaHash<'a, G> {
    pub(super) fn gen_omega(self) -> (Vec<G::Zp>, OmegaHash<'a, G>) {
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

        let mut omega = vec![G::Zp::ZERO; R_inputs.n];
        G::Zp::hash_128bit(
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
                R_inputs.C_hat_e.to_le_bytes().as_ref(),
                R_inputs.C_e.to_le_bytes().as_ref(),
                &R_bytes,
                phi_inputs.C_R.to_le_bytes().as_ref(),
                xi_inputs.C_hat_bin.to_le_bytes().as_ref(),
                R_inputs.C_r_tilde.to_le_bytes().as_ref(),
                t_inputs.C_y.to_le_bytes().as_ref(),
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

pub(super) struct OmegaHash<'a, G: Curve> {
    R_inputs: RInputs<'a, G>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<G>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<G>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<G>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
    omega_bytes: Box<[u8]>,
}

impl<'a, G: Curve> OmegaHash<'a, G> {
    pub(super) fn gen_delta(self) -> ([G::Zp; 7], DeltaHash<'a, G>) {
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

        let mut delta = [G::Zp::ZERO; 7];
        G::Zp::hash(
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
                R_inputs.C_hat_e.to_le_bytes().as_ref(),
                R_inputs.C_e.to_le_bytes().as_ref(),
                &R_bytes,
                phi_inputs.C_R.to_le_bytes().as_ref(),
                xi_inputs.C_hat_bin.to_le_bytes().as_ref(),
                R_inputs.C_r_tilde.to_le_bytes().as_ref(),
                t_inputs.C_y.to_le_bytes().as_ref(),
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

pub(super) struct DeltaHash<'a, G: Curve> {
    R_inputs: RInputs<'a, G>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<G>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<G>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<G>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
    delta_bytes: Box<[u8]>,
}

impl<'a, G: Curve> DeltaHash<'a, G> {
    pub(super) fn gen_z(
        self,
        C_h1: G::G1,
        C_h2: G::G1,
        C_hat_t: G::G2,
        compute_load_proof_fields: Option<ComputeLoadProofFields<G>>,
    ) -> (G::Zp, ZHash<'a, G>) {
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

        let (C_hat_h3_bytes, C_hat_w_bytes) =
            ComputeLoadProofFields::to_le_bytes(&compute_load_proof_fields);

        let mut z = G::Zp::ZERO;
        G::Zp::hash(
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
                R_inputs.C_hat_e.to_le_bytes().as_ref(),
                R_inputs.C_e.to_le_bytes().as_ref(),
                &R_bytes,
                phi_inputs.C_R.to_le_bytes().as_ref(),
                xi_inputs.C_hat_bin.to_le_bytes().as_ref(),
                R_inputs.C_r_tilde.to_le_bytes().as_ref(),
                t_inputs.C_y.to_le_bytes().as_ref(),
                C_h1.to_le_bytes().as_ref(),
                C_h2.to_le_bytes().as_ref(),
                C_hat_t.to_le_bytes().as_ref(),
                &C_hat_h3_bytes,
                &C_hat_w_bytes,
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
                    C_h1,
                    C_h2,
                    C_hat_t,
                    compute_load_proof_fields,
                },
                z,
            },
        )
    }
}

struct ZInputs<G: Curve> {
    C_h1: G::G1,
    C_h2: G::G1,
    C_hat_t: G::G2,
    compute_load_proof_fields: Option<ComputeLoadProofFields<G>>,
}

pub(super) struct ZHash<'a, G: Curve> {
    R_inputs: RInputs<'a, G>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<G>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<G>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<G>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
    delta_bytes: Box<[u8]>,
    z_inputs: ZInputs<G>,
    z: G::Zp,
}

impl<'a, G: Curve> ZHash<'a, G> {
    pub(super) fn gen_chi(self, p_h1: G::Zp, p_h2: G::Zp, p_t: G::Zp) -> G::Zp {
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

        let (C_hat_h3_bytes, C_hat_w_bytes) =
            ComputeLoadProofFields::to_le_bytes(&z_inputs.compute_load_proof_fields);

        let mut chi = G::Zp::ZERO;
        G::Zp::hash(
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
                R_inputs.C_hat_e.to_le_bytes().as_ref(),
                R_inputs.C_e.to_le_bytes().as_ref(),
                &R_bytes,
                phi_inputs.C_R.to_le_bytes().as_ref(),
                xi_inputs.C_hat_bin.to_le_bytes().as_ref(),
                R_inputs.C_r_tilde.to_le_bytes().as_ref(),
                t_inputs.C_y.to_le_bytes().as_ref(),
                z_inputs.C_h1.to_le_bytes().as_ref(),
                z_inputs.C_h2.to_le_bytes().as_ref(),
                z_inputs.C_hat_t.to_le_bytes().as_ref(),
                &C_hat_h3_bytes,
                &C_hat_w_bytes,
                z.to_le_bytes().as_ref(),
                p_h1.to_le_bytes().as_ref(),
                p_h2.to_le_bytes().as_ref(),
                p_t.to_le_bytes().as_ref(),
            ],
        );

        chi
    }
}
