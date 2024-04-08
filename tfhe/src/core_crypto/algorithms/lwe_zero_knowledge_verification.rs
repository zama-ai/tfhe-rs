use crate::core_crypto::entities::{LweCompactCiphertextList, LweCompactPublicKey};
use crate::core_crypto::prelude::{CastFrom, Container, LweCiphertext, UnsignedInteger};
use crate::zk::{CompactPkeProof, CompactPkePublicParams, ZkVerificationOutCome};
use tfhe_zk_pok::proofs::pke::{verify, PublicCommit};

/// Verifies with the given proof that a [`LweCompactCiphertextList`](LweCompactCiphertextList)
/// is valid.
pub fn verify_lwe_compact_ciphertext_list<Scalar, ListCont, KeyCont>(
    lwe_compact_list: &LweCompactCiphertextList<ListCont>,
    compact_public_key: &LweCompactPublicKey<KeyCont>,
    proof: &CompactPkeProof,
    public_params: &CompactPkePublicParams,
) -> ZkVerificationOutCome
where
    Scalar: UnsignedInteger,
    i64: CastFrom<Scalar>,
    ListCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
{
    if Scalar::BITS > 64 {
        return ZkVerificationOutCome::Invalid;
    }
    let public_commit = PublicCommit::new(
        compact_public_key
            .get_mask()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect(),
        compact_public_key
            .get_body()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect(),
        lwe_compact_list
            .get_mask_list()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect(),
        lwe_compact_list
            .get_body_list()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect(),
    );
    match verify(proof, (public_params, &public_commit)) {
        Ok(_) => ZkVerificationOutCome::Valid,
        Err(_) => ZkVerificationOutCome::Invalid,
    }
}

pub fn verify_lwe_ciphertext<Scalar, Cont, KeyCont>(
    lwe_ciphertext: &LweCiphertext<Cont>,
    compact_public_key: &LweCompactPublicKey<KeyCont>,
    proof: &CompactPkeProof,
    public_params: &CompactPkePublicParams,
) -> ZkVerificationOutCome
where
    Scalar: UnsignedInteger,
    i64: CastFrom<Scalar>,
    Cont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
{
    if Scalar::BITS > 64 {
        return ZkVerificationOutCome::Invalid;
    }
    let public_commit = PublicCommit::new(
        compact_public_key
            .get_mask()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect(),
        compact_public_key
            .get_body()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect(),
        lwe_ciphertext
            .get_mask()
            .as_ref()
            .iter()
            .copied()
            .map(|x| i64::cast_from(x))
            .collect(),
        vec![i64::cast_from(*lwe_ciphertext.get_body().data); 1],
    );
    match verify(proof, (public_params, &public_commit)) {
        Ok(_) => ZkVerificationOutCome::Valid,
        Err(_) => ZkVerificationOutCome::Invalid,
    }
}
