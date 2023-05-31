use super::client_key::FheBoolClientKey;
use super::types::FheBool;
use crate::boolean::server_key::{BinaryBooleanGates, CompressedServerKey, ServerKey};

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FheBoolServerKey {
    pub(in crate::high_level_api::booleans) key: ServerKey,
}

impl FheBoolServerKey {
    pub(crate) fn new(key: &FheBoolClientKey) -> Self {
        Self {
            key: ServerKey::new(&key.key),
        }
    }

    pub(in crate::high_level_api::booleans) fn and(&self, lhs: &FheBool, rhs: &FheBool) -> FheBool {
        let ciphertext = self.key.and(&lhs.ciphertext, &rhs.ciphertext);
        FheBool::new(ciphertext)
    }

    pub(in crate::high_level_api::booleans) fn or(&self, lhs: &FheBool, rhs: &FheBool) -> FheBool {
        let ciphertext = self.key.or(&lhs.ciphertext, &rhs.ciphertext);
        FheBool::new(ciphertext)
    }

    pub(in crate::high_level_api::booleans) fn xor(&self, lhs: &FheBool, rhs: &FheBool) -> FheBool {
        let ciphertext = self.key.xor(&lhs.ciphertext, &rhs.ciphertext);
        FheBool::new(ciphertext)
    }

    pub(in crate::high_level_api::booleans) fn xnor(
        &self,
        lhs: &FheBool,
        rhs: &FheBool,
    ) -> FheBool {
        let ciphertext = self.key.xnor(&lhs.ciphertext, &rhs.ciphertext);
        FheBool::new(ciphertext)
    }

    pub(in crate::high_level_api::booleans) fn nand(
        &self,
        lhs: &FheBool,
        rhs: &FheBool,
    ) -> FheBool {
        let ciphertext = self.key.nand(&lhs.ciphertext, &rhs.ciphertext);
        FheBool::new(ciphertext)
    }

    pub(in crate::high_level_api::booleans) fn not(&self, lhs: &FheBool) -> FheBool {
        let ciphertext = self.key.not(&lhs.ciphertext);
        FheBool::new(ciphertext)
    }

    #[allow(dead_code)]
    pub(in crate::high_level_api::booleans) fn mux(
        &self,
        condition: &FheBool,
        then_result: &FheBool,
        else_result: &FheBool,
    ) -> FheBool {
        let ciphertext = self.key.mux(
            &condition.ciphertext,
            &then_result.ciphertext,
            &else_result.ciphertext,
        );
        FheBool::new(ciphertext)
    }
}

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FheBoolCompressedServerKey {
    pub(in crate::high_level_api::booleans) key: CompressedServerKey,
}

impl FheBoolCompressedServerKey {
    pub(in crate::high_level_api::booleans) fn new(client_key: &FheBoolClientKey) -> Self {
        Self {
            key: CompressedServerKey::new(&client_key.key),
        }
    }

    pub(in crate::high_level_api::booleans) fn decompress(self) -> FheBoolServerKey {
        FheBoolServerKey {
            key: self.key.into(),
        }
    }
}
