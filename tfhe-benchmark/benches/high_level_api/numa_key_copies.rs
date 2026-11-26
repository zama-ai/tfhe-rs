//! One copy of the server key per NUMA node for the high-level API benchmarks, each PBS
//! using the copy of the node its thread runs on.
//!
//! The KS32 atomic pattern of the server key is wrapped in an atomic pattern of the
//! `Dynamic` variant that holds one copy of it per node and forwards every call to the copy
//! local to the calling thread. Every integer operation applies its lookup tables through
//! the atomic pattern, so all of them use local keys, without changing TFHE-rs.

use benchmark::numa::{region, NumaReplicated};
use std::sync::Arc;
use tfhe::core_crypto::prelude::{LweDimension, MsDecompressionType};
use tfhe::shortint::atomic_pattern::{
    AtomicPattern, AtomicPatternKind, AtomicPatternMut, AtomicPatternServerKey,
    KS32AtomicPatternServerKey,
};
use tfhe::shortint::ciphertext::CompressedModulusSwitchedCiphertext;
use tfhe::shortint::server_key::{
    LookupTableOwned, LookupTableSize, ManyLookupTableOwned, ShortintBootstrappingKey,
};
use tfhe::shortint::{Ciphertext, CiphertextModulus, EncryptionKeyChoice};

/// A KS32 atomic pattern copied once per NUMA node.
#[derive(Clone)]
struct NumaKs32(Arc<NumaReplicated<KS32AtomicPatternServerKey>>);

impl std::fmt::Debug for NumaKs32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NumaKs32 {{ copies: {} }}", self.0.len())
    }
}

impl PartialEq for NumaKs32 {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl AtomicPattern for NumaKs32 {
    fn ciphertext_lwe_dimension_for_key(&self, key_choice: EncryptionKeyChoice) -> LweDimension {
        self.0.local().ciphertext_lwe_dimension_for_key(key_choice)
    }

    fn ciphertext_modulus_for_key(&self, key_choice: EncryptionKeyChoice) -> CiphertextModulus {
        self.0.local().ciphertext_modulus_for_key(key_choice)
    }

    fn ciphertext_decompression_method(&self) -> MsDecompressionType {
        self.0.local().ciphertext_decompression_method()
    }

    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        self.0.local().apply_lookup_table_assign(ct, acc)
    }

    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        self.0.local().apply_many_lookup_table(ct, lut)
    }

    fn lookup_table_size(&self) -> LookupTableSize {
        self.0.local().lookup_table_size()
    }

    fn kind(&self) -> AtomicPatternKind {
        self.0.local().kind()
    }

    fn deterministic_execution(&self) -> bool {
        self.0.local().deterministic_execution()
    }

    fn switch_modulus_and_compress(&self, ct: &Ciphertext) -> CompressedModulusSwitchedCiphertext {
        self.0.local().switch_modulus_and_compress(ct)
    }

    fn decompress_and_apply_lookup_table(
        &self,
        compressed_ct: &CompressedModulusSwitchedCiphertext,
        lut: &LookupTableOwned,
    ) -> Ciphertext {
        self.0
            .local()
            .decompress_and_apply_lookup_table(compressed_ct, lut)
    }
}

impl AtomicPatternMut for NumaKs32 {
    fn set_deterministic_execution(&mut self, _: bool) {
        panic!("the NUMA key copies are read only");
    }
}

/// `sks` with its KS32 keyswitching and bootstrapping keys copied once per NUMA node, each
/// copy bound to its node.
pub fn replicate(sks: tfhe::ServerKey) -> tfhe::ServerKey {
    let (
        key,
        cpk_ksk,
        compression,
        decompression,
        squashing,
        squashing_compression,
        rerand,
        oprf,
        transciphering,
        tag,
    ) = sks.into_raw_parts();
    let mut shortint = key.into_raw_parts();
    let AtomicPatternServerKey::KeySwitch32(ap) = shortint.atomic_pattern else {
        panic!("NUMA key copies need the KS32 atomic pattern");
    };
    let copies = NumaReplicated::new_bound(&ap, |ap: &KS32AtomicPatternServerKey| {
        let bsk = match &ap.bootstrapping_key {
            ShortintBootstrappingKey::Classic { bsk, .. } => region(bsk.as_view().data()),
            ShortintBootstrappingKey::MultiBit { .. } => {
                panic!("NUMA key copies support the classic PBS only")
            }
        };
        vec![region(ap.key_switching_key.as_ref()), bsk]
    });
    drop(ap);
    println!("NUMA key copies: {}", copies.len());
    shortint.atomic_pattern = AtomicPatternServerKey::Dynamic(Box::new(NumaKs32(Arc::new(copies))));
    tfhe::ServerKey::from_raw_parts(
        tfhe::integer::ServerKey::from_raw_parts(shortint),
        cpk_ksk,
        compression,
        decompression,
        squashing,
        squashing_compression,
        rerand,
        oprf,
        transciphering,
        tag,
    )
}
