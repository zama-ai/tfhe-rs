use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::curve_api::{CompressedG1, CompressedG2, Compressible, Curve};
use crate::proofs::pke::{
    CompressedComputeLoadProofFields, CompressedProof, ComputeLoadProofFields, Proof,
};

use super::IncompleteProof;

#[derive(Version)]
pub struct ProofV0<G: Curve> {
    c_hat: G::G2,
    c_y: G::G1,
    pi: G::G1,
    c_hat_t: Option<G::G2>,
    c_h: Option<G::G1>,
    pi_kzg: Option<G::G1>,
}

impl<G: Curve> Upgrade<Proof<G>> for ProofV0<G> {
    type Error = IncompleteProof;

    fn upgrade(self) -> Result<Proof<G>, Self::Error> {
        let Self {
            c_hat,
            c_y,
            pi,
            c_hat_t,
            c_h,
            pi_kzg,
        } = self;

        let compute_load_proof_fields = match (c_hat_t, c_h, pi_kzg) {
            (None, None, None) => None,
            (Some(c_hat_t), Some(c_h), Some(pi_kzg)) => Some(ComputeLoadProofFields {
                c_hat_t,
                c_h,
                pi_kzg,
            }),
            _ => {
                return Err(IncompleteProof);
            }
        };

        Ok(Proof {
            c_hat,
            c_y,
            pi,
            compute_load_proof_fields,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum ProofVersions<G: Curve> {
    V0(ProofV0<G>),
    V1(Proof<G>),
}

#[derive(VersionsDispatch)]
pub(crate) enum ComputeLoadProofFieldsVersions<G: Curve> {
    #[allow(dead_code)]
    V0(ComputeLoadProofFields<G>),
}

pub struct CompressedProofV0<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    c_hat: CompressedG2<G>,
    c_y: CompressedG1<G>,
    pi: CompressedG1<G>,
    c_hat_t: Option<CompressedG2<G>>,
    c_h: Option<CompressedG1<G>>,
    pi_kzg: Option<CompressedG1<G>>,
}

impl<G: Curve> Upgrade<CompressedProof<G>> for CompressedProofV0<G>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    type Error = IncompleteProof;

    fn upgrade(self) -> Result<CompressedProof<G>, Self::Error> {
        let Self {
            c_hat,
            c_y,
            pi,
            c_hat_t,
            c_h,
            pi_kzg,
        } = self;

        let compute_load_proof_fields = match (c_hat_t, c_h, pi_kzg) {
            (None, None, None) => None,
            (Some(c_hat_t), Some(c_h), Some(pi_kzg)) => Some(CompressedComputeLoadProofFields {
                c_hat_t,
                c_h,
                pi_kzg,
            }),
            _ => {
                return Err(IncompleteProof);
            }
        };

        Ok(CompressedProof {
            c_hat,
            c_y,
            pi,
            compute_load_proof_fields,
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
