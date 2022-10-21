//! A module containing various marker traits used for entities.
use std::fmt::Debug;

/// A trait implemented by marker types encoding the __kind__ of an FHE entity in
/// the type system.
///
/// By _kind_ here, we mean the _what_, the abstract nature of an FHE entity.
///
/// # Note
///
/// [`EntityKindMarker`] types are only defined in the specification part of the library, and
/// can not be defined by a backend.
pub trait EntityKindMarker: seal::EntityKindMarkerSealed {}
macro_rules! entity_kind_marker {
        (@ $name: ident => $doc: literal)=>{
            #[doc=$doc]
            #[derive(Debug, Clone, Copy)]
            pub struct $name{}
            impl seal::EntityKindMarkerSealed for $name{}
            impl EntityKindMarker for $name{}
        };
        ($($name: ident => $doc: literal),+) =>{
            $(
                entity_kind_marker!(@ $name => $doc);
            )+
        }
}
entity_kind_marker! {
        PlaintextKind
            => "An empty type representing the plaintext kind in the type system.",
        PlaintextVectorKind
            => "An empty type representing the plaintext vector kind in the type system",
        CleartextKind
            => "An empty type representing the cleartext kind in the type system.",
        CleartextVectorKind
            => "An empty type representing the cleartext vector kind in the type system.",
        LweCiphertextKind
            => "An empty type representing the LWE ciphertext kind in the type system.",
        LweCiphertextVectorKind
            => "An empty type representing the LWE ciphertext vector kind in the type system.",
        LweSeededCiphertextKind
            => "An empty type representing the seeded LWE ciphertext kind in the type system.",
        LweSeededCiphertextVectorKind
            => "An empty type representing the seeded LWE ciphertext vector kind in the type system.",
        GlweCiphertextKind
            => "An empty type representing the GLWE ciphertext kind in the type system.",
        GlweCiphertextVectorKind
            => "An empty type representing the GLWE ciphertext vector kind in the type system.",
        GlweSeededCiphertextKind
            => "An empty type representing the seeded GLWE ciphertext kind in the type system.",
        GlweSeededCiphertextVectorKind
            => "An empty type representing the seeded GLWE ciphertext vector kind in the type system.",
        GgswCiphertextKind
            => "An empty type representing the GGSW ciphertext kind in the type system.",
        GgswCiphertextVectorKind
            => "An empty type representing the GGSW ciphertext vector kind in the type system.",
        GgswSeededCiphertextKind
            => "An empty type representing the seeded GGSW ciphertext kind in the type system.",
        GswCiphertextKind
            => "An empty type representing the GSW ciphertext kind in the type system.",
        GswCiphertextVectorKind
            => "An empty type representing the GSW ciphertext vector kind in the type system.",
        LwePublicKeyKind
            => "An empty type representing the LWE public key kind in the type system.",
        LweSecretKeyKind
            => "An empty type representing the LWE secret key kind in the type system.",
        GlweSecretKeyKind
            => "An empty type representing the GLWE secret key kind in the type system.",
        LweKeyswitchKeyKind
            => "An empty type representing the LWE keyswitch key kind in the type system.",
        LweSeededKeyswitchKeyKind
            => "An empty type representing the seeded LWE keyswitch key kind in the type system.",
        LwePackingKeyswitchKeyKind
            => "An empty type representing the packing keyswitch key kind in the type system.",
        LwePrivateFunctionalPackingKeyswitchKeyKind
            => "An empty type representing the private functional packing keyswitch key in the \
            type system.",
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind
            => "An empty type representing the private functional packing keyswitch key vector \
            used for a circuit bootstrap in the type system.",
        LweBootstrapKeyKind
            => "An empty type representing the LWE bootstrap key kind in the type system.",
        LweSeededBootstrapKeyKind
            => "An empty type representing the seeded LWE bootstrap key kind in the type system.",
        EncoderKind
            => "An empty type representing the encoder kind in the type system.",
        EncoderVectorKind
            => "An empty type representing the encoder vector kind in the type system"
}

pub(crate) mod seal {
    pub trait EntityKindMarkerSealed {}
}
