// to follow the notation of the paper
#![allow(non_snake_case)]

use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::curve_api::{CompressedG1, CompressedG2, Compressible, Curve};
use crate::proofs::pke_v2::{
    CompressedComputeLoadProofFields, CompressedProof, ComputeLoadProofFields, PkeV2HashMode, Proof,
};

use super::IncompleteProof;

#[derive(Version)]
pub struct ProofV0<G: Curve> {
    C_hat_e: G::G2,
    C_e: G::G1,
    C_r_tilde: G::G1,
    C_R: G::G1,
    C_hat_bin: G::G2,
    C_y: G::G1,
    C_h1: G::G1,
    C_h2: G::G1,
    C_hat_t: G::G2,
    pi: G::G1,
    pi_kzg: G::G1,

    C_hat_h3: Option<G::G2>,
    C_hat_w: Option<G::G2>,
}

impl<G: Curve> Upgrade<ProofV1<G>> for ProofV0<G> {
    type Error = IncompleteProof;

    fn upgrade(self) -> Result<ProofV1<G>, Self::Error> {
        let ProofV0 {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            C_hat_h3,
            C_hat_w,
        } = self;

        let compute_load_proof_fields = match (C_hat_h3, C_hat_w) {
            (None, None) => None,
            (Some(C_hat_h3), Some(C_hat_w)) => Some(ComputeLoadProofFields { C_hat_h3, C_hat_w }),
            _ => return Err(IncompleteProof),
        };

        Ok(ProofV1 {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            compute_load_proof_fields,
        })
    }
}

#[derive(Version)]
pub struct ProofV1<G: Curve> {
    C_hat_e: G::G2,
    C_e: G::G1,
    C_r_tilde: G::G1,
    C_R: G::G1,
    C_hat_bin: G::G2,
    C_y: G::G1,
    C_h1: G::G1,
    C_h2: G::G1,
    C_hat_t: G::G2,
    pi: G::G1,
    pi_kzg: G::G1,
    compute_load_proof_fields: Option<ComputeLoadProofFields<G>>,
}

impl<G: Curve> Upgrade<Proof<G>> for ProofV1<G> {
    type Error = Infallible;

    fn upgrade(self) -> Result<Proof<G>, Self::Error> {
        let ProofV1 {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            compute_load_proof_fields,
        } = self;

        Ok(Proof {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            compute_load_proof_fields,
            hash_mode: PkeV2HashMode::BackwardCompat,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum ProofVersions<G: Curve> {
    V0(ProofV0<G>),
    V1(ProofV1<G>),
    V2(Proof<G>),
}

#[derive(VersionsDispatch)]
pub(crate) enum ComputeLoadProofFieldsVersions<G: Curve> {
    #[allow(dead_code)]
    V0(ComputeLoadProofFields<G>),
}

#[derive(Version)]
pub struct CompressedProofV0<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    C_hat_e: CompressedG2<G>,
    C_e: CompressedG1<G>,
    C_r_tilde: CompressedG1<G>,
    C_R: CompressedG1<G>,
    C_hat_bin: CompressedG2<G>,
    C_y: CompressedG1<G>,
    C_h1: CompressedG1<G>,
    C_h2: CompressedG1<G>,
    C_hat_t: CompressedG2<G>,
    pi: CompressedG1<G>,
    pi_kzg: CompressedG1<G>,

    C_hat_h3: Option<CompressedG2<G>>,
    C_hat_w: Option<CompressedG2<G>>,
}

impl<G: Curve> Upgrade<CompressedProofV1<G>> for CompressedProofV0<G>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    type Error = IncompleteProof;

    fn upgrade(self) -> Result<CompressedProofV1<G>, Self::Error> {
        let CompressedProofV0 {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            C_hat_h3,
            C_hat_w,
        } = self;

        let compute_load_proof_fields = match (C_hat_h3, C_hat_w) {
            (None, None) => None,
            (Some(C_hat_h3), Some(C_hat_w)) => {
                Some(CompressedComputeLoadProofFields { C_hat_h3, C_hat_w })
            }
            _ => return Err(IncompleteProof),
        };

        Ok(CompressedProofV1 {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            compute_load_proof_fields,
        })
    }
}

#[derive(Version)]
pub struct CompressedProofV1<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    C_hat_e: CompressedG2<G>,
    C_e: CompressedG1<G>,
    C_r_tilde: CompressedG1<G>,
    C_R: CompressedG1<G>,
    C_hat_bin: CompressedG2<G>,
    C_y: CompressedG1<G>,
    C_h1: CompressedG1<G>,
    C_h2: CompressedG1<G>,
    C_hat_t: CompressedG2<G>,
    pi: CompressedG1<G>,
    pi_kzg: CompressedG1<G>,
    compute_load_proof_fields: Option<CompressedComputeLoadProofFields<G>>,
}

impl<G: Curve> Upgrade<CompressedProof<G>> for CompressedProofV1<G>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedProof<G>, Self::Error> {
        let CompressedProofV1 {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            compute_load_proof_fields,
        } = self;

        Ok(CompressedProof {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            compute_load_proof_fields,
            hash_mode: PkeV2HashMode::BackwardCompat,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedProofVersions<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    V0(CompressedProofV0<G>),
    V1(CompressedProof<G>),
}

#[derive(VersionsDispatch)]
pub(crate) enum CompressedComputeLoadProofFieldsVersions<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    #[allow(dead_code)]
    V0(CompressedComputeLoadProofFields<G>),
}

#[derive(VersionsDispatch)]
pub enum PkeV2HashModeVersions {
    #[allow(dead_code)]
    V0(PkeV2HashMode),
}
