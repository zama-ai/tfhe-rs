use crate::core_crypto::entities::{LweCompactCiphertextList, LweCompactPublicKey};
use crate::core_crypto::prelude::{
    CastFrom, Container, LweCiphertext, LweCiphertextCount, UnsignedInteger,
};
use crate::zk::{CompactPkeCrs, CompactPkeProof, ZkVerificationOutcome};

/// Verifies with the given proof that a [`LweCompactCiphertextList`]
/// is valid.
pub fn verify_lwe_compact_ciphertext_list<Scalar, ListCont, KeyCont>(
    lwe_compact_list: &LweCompactCiphertextList<ListCont>,
    compact_public_key: &LweCompactPublicKey<KeyCont>,
    proof: &CompactPkeProof,
    crs: &CompactPkeCrs,
    metadata: &[u8],
) -> ZkVerificationOutcome
where
    Scalar: UnsignedInteger,
    i64: CastFrom<Scalar>,
    ListCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
{
    crs.verify(lwe_compact_list, compact_public_key, proof, metadata)
}

/// Verifies with the given proof that a single [`LweCiphertext`] is valid.
pub fn verify_lwe_ciphertext<Scalar, Cont, KeyCont>(
    lwe_ciphertext: &LweCiphertext<Cont>,
    compact_public_key: &LweCompactPublicKey<KeyCont>,
    proof: &CompactPkeProof,
    crs: &CompactPkeCrs,
    metadata: &[u8],
) -> ZkVerificationOutcome
where
    Scalar: UnsignedInteger,
    i64: CastFrom<Scalar>,
    Cont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
{
    crs.verify(
        &LweCompactCiphertextList::from_container(
            lwe_ciphertext.as_ref(),
            lwe_ciphertext.lwe_size(),
            LweCiphertextCount(1),
            lwe_ciphertext.ciphertext_modulus(),
        ),
        compact_public_key,
        proof,
        metadata,
    )
}
