use tfhe_versionable::VersionsDispatch;

use crate::commons::ciphertext_modulus::SerializableCiphertextModulus;

#[derive(VersionsDispatch)]
pub enum SerializableCiphertextModulusVersions {
    V0(SerializableCiphertextModulus),
}
