//! Selective decompression: fetch individual parts of a [`CompressedXofKeySet`] without
//! materializing the whole server key.
//!
//! Each call rebuilds a fresh mask generator from the seed and fast-forwards (skips) past every
//! component preceding the requested one, so calls are independent and order-free.

use super::CompressedXofKeySet;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::prelude::DefaultRandomGenerator;
use crate::high_level_api::keys::expanded::{
    compute_key_to_cpu, expanded_decompression_key_to_cpu, expanded_noise_squashing_key_to_cpu,
    ShortintExpandedServerKey,
};
use crate::high_level_api::keys::ReRandomizationKey;
use crate::integer::ciphertext::NoiseSquashingCompressionKey;
use crate::integer::compression_keys::{CompressionKey, DecompressionKey};
use crate::integer::key_switching_key::KeySwitchingKeyMaterial;
use crate::integer::noise_squashing::NoiseSquashingKey;
use crate::integer::oprf::OprfServerKey;
use crate::prelude::Tagged;
use crate::{integer, CompactPublicKey};

/// Position of a component in the XOF mask stream (its generation/decompression order).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    PublicKey,
    Compression,
    Decompression,
    Compute,
    NoiseSquashing,
    CpkKsk,
    ReRand,
    NsCompression,
    Oprf,
}

mod sealed {
    pub trait Sealed {}
}
use self::sealed::Sealed;

/// A selection of parts that can be decompressed from a [`CompressedXofKeySet`] via
/// [`CompressedXofKeySet::decompress_parts`].
///
/// The trait is sealed. Implemented for `CompactPublicKey`, the compute `integer::ServerKey` and
/// for `Option<K>` of each optional part, and for tuples of these.
pub trait XofParts: Sized + Sealed {
    #[doc(hidden)]
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self;
}

impl CompressedXofKeySet {
    /// Decompress only the requested part(s).
    ///
    /// `K` selects what is returned: an always-present part (the public key or the compute server
    /// key), an `Option` of any optional key, or a tuple of up to four of these.
    pub fn decompress_parts<K: XofParts>(&self) -> K {
        K::decompress_parts(self)
    }

    /// A fresh mask generator seeded from the key set, fast-forwarded to `target`'s position by
    /// skipping every present component before it.
    fn generator_at(&self, target: Slot) -> MaskRandomGenerator<DefaultRandomGenerator> {
        #[allow(clippy::enum_glob_use)]
        use Slot::*;

        let mut gen = MaskRandomGenerator::new(self.seed.clone());
        let icsk = &self.compressed_server_key.integer_key;

        // Skip each present component, in stream order, until we reach `target`.
        for slot in [
            PublicKey,
            Compression,
            Decompression,
            Compute,
            NoiseSquashing,
            CpkKsk,
            ReRand,
            NsCompression,
            Oprf,
        ] {
            if slot >= target {
                break;
            }
            match slot {
                PublicKey => self.compressed_public_key.advance_generator(&mut gen),
                Compression => {
                    if let Some(k) = icsk.compression_key.as_ref() {
                        k.advance_generator(&mut gen);
                    }
                }
                Decompression => {
                    if let Some(k) = icsk.decompression_key.as_ref() {
                        k.advance_generator(&mut gen);
                    }
                }
                Compute => icsk
                    .key
                    .key
                    .compressed_ap_server_key
                    .advance_generator(&mut gen),
                NoiseSquashing => {
                    if let Some(k) = icsk.noise_squashing_key.as_ref() {
                        k.advance_generator(&mut gen);
                    }
                }
                CpkKsk => {
                    if let Some(k) = icsk.cpk_key_switching_key_material.as_ref() {
                        k.advance_generator(&mut gen);
                    }
                }
                ReRand => {
                    if let Some(k) = icsk.cpk_re_randomization_key.as_ref() {
                        k.advance_generator(&mut gen);
                    }
                }
                NsCompression => {
                    if let Some(k) = icsk.noise_squashing_compression_key.as_ref() {
                        k.advance_generator(&mut gen);
                    }
                }
                Oprf => break,
            }
        }

        gen
    }
}

impl Sealed for CompactPublicKey {}
impl XofParts for CompactPublicKey {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        let mut gen = keyset.generator_at(Slot::PublicKey);

        let mut public_key = keyset
            .compressed_public_key
            .decompress_with_pre_seeded_generator(&mut gen);
        // Server key tag is the source of truth.
        public_key
            .tag_mut()
            .set_data(keyset.compressed_server_key.tag.data());
        public_key
    }
}

impl Sealed for crate::integer::ServerKey {}
impl XofParts for crate::integer::ServerKey {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        let mut gen = keyset.generator_at(Slot::Compute);
        let shortint_csk = &keyset.compressed_server_key.integer_key.key.key;

        let compute_key = ShortintExpandedServerKey {
            atomic_pattern: shortint_csk
                .compressed_ap_server_key
                .decompress_with_pre_seeded_generator(&mut gen),
            message_modulus: shortint_csk.message_modulus,
            carry_modulus: shortint_csk.carry_modulus,
            max_degree: shortint_csk.max_degree,
            max_noise_level: shortint_csk.max_noise_level,
            ciphertext_modulus: shortint_csk.ciphertext_modulus(),
        };
        compute_key_to_cpu(compute_key)
    }
}

impl Sealed for CompressionKey {}
impl XofParts for Option<CompressionKey> {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        let compressed = keyset
            .compressed_server_key
            .integer_key
            .compression_key
            .as_ref()?;
        let mut gen = keyset.generator_at(Slot::Compression);
        Some(compressed.decompress_with_pre_seeded_generator(&mut gen))
    }
}

impl Sealed for DecompressionKey {}
impl XofParts for Option<DecompressionKey> {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        let compressed = keyset
            .compressed_server_key
            .integer_key
            .decompression_key
            .as_ref()?;
        let mut gen = keyset.generator_at(Slot::Decompression);
        Some(expanded_decompression_key_to_cpu(
            compressed.decompress_with_pre_seeded_generator(&mut gen),
        ))
    }
}

impl Sealed for NoiseSquashingKey {}
impl XofParts for Option<NoiseSquashingKey> {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        let compressed = keyset
            .compressed_server_key
            .integer_key
            .noise_squashing_key
            .as_ref()?;
        let mut gen = keyset.generator_at(Slot::NoiseSquashing);
        Some(expanded_noise_squashing_key_to_cpu(
            compressed.decompress_with_pre_seeded_generator(&mut gen),
        ))
    }
}

impl Sealed for KeySwitchingKeyMaterial {}
impl XofParts for Option<KeySwitchingKeyMaterial> {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        let compressed = keyset
            .compressed_server_key
            .integer_key
            .cpk_key_switching_key_material
            .as_ref()?;
        let mut gen = keyset.generator_at(Slot::CpkKsk);
        Some(compressed.decompress_with_pre_seeded_generator(&mut gen))
    }
}

impl Sealed for NoiseSquashingCompressionKey {}
impl XofParts for Option<NoiseSquashingCompressionKey> {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        let compressed = keyset
            .compressed_server_key
            .integer_key
            .noise_squashing_compression_key
            .as_ref()?;
        let mut gen = keyset.generator_at(Slot::NsCompression);
        Some(compressed.decompress_with_pre_seeded_generator(&mut gen))
    }
}

impl Sealed for ReRandomizationKey {}
impl XofParts for Option<ReRandomizationKey> {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        let compressed = keyset
            .compressed_server_key
            .integer_key
            .cpk_re_randomization_key
            .as_ref()?;
        let mut gen = keyset.generator_at(Slot::ReRand);
        Some(compressed.decompress_with_pre_seeded_generator(&mut gen))
    }
}

impl Sealed for OprfServerKey {}
impl XofParts for Option<OprfServerKey> {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        let compressed = keyset.compressed_server_key.integer_key.oprf_key.as_ref()?;
        let mut gen = keyset.generator_at(Slot::Oprf);
        Some(
            compressed
                .decompress_with_pre_seeded_generator(&mut gen)
                .to_fourier(),
        )
    }
}

impl<K: Sealed> Sealed for Option<K> {}

impl<A: Sealed, B: Sealed> Sealed for (A, B) {}
impl<A: XofParts, B: XofParts> XofParts for (A, B) {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        (A::decompress_parts(keyset), B::decompress_parts(keyset))
    }
}

impl<A: Sealed, B: Sealed, C: Sealed> Sealed for (A, B, C) {}
impl<A: XofParts, B: XofParts, C: XofParts> XofParts for (A, B, C) {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        (
            A::decompress_parts(keyset),
            B::decompress_parts(keyset),
            C::decompress_parts(keyset),
        )
    }
}

impl<A: Sealed, B: Sealed, C: Sealed, D: Sealed> Sealed for (A, B, C, D) {}
impl<A: XofParts, B: XofParts, C: XofParts, D: XofParts> XofParts for (A, B, C, D) {
    fn decompress_parts(keyset: &CompressedXofKeySet) -> Self {
        (
            A::decompress_parts(keyset),
            B::decompress_parts(keyset),
            C::decompress_parts(keyset),
            D::decompress_parts(keyset),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_crypto::prelude::NormalizedHammingWeightBound;
    use crate::shortint::parameters::test_params::TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
    use crate::{integer, Tag};

    fn keyset() -> CompressedXofKeySet {
        let config = TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128.into();
        CompressedXofKeySet::generate(
            config,
            vec![9u8; 32],
            128,
            NormalizedHammingWeightBound::new(0.8).unwrap(),
            Tag::default(),
        )
        .unwrap()
        .1
    }

    fn ser<T: serde::Serialize>(value: &T) -> Vec<u8> {
        bincode::serialize(value).unwrap()
    }

    /// Every single-part fetch must byte-match the corresponding piece of a full
    /// `decompress().into_raw_parts()` — bare for the always-present parts, `Option` for the rest
    /// (matching the `Option` from `into_raw_parts`, present or absent).
    #[test]
    fn single_parts_match_full_decompress() {
        let ks = keyset();

        let (public_key, server_key) = ks.decompress().into_raw_parts();
        let (
            isk,
            cpk_ksk,
            compression,
            decompression,
            noise_squashing,
            ns_compression,
            re_rand,
            oprf,
            _tag,
        ) = server_key.into_raw_parts();

        assert_eq!(
            ser(&ks.decompress_parts::<CompactPublicKey>()),
            ser(&public_key)
        );
        assert_eq!(ser(&ks.decompress_parts::<integer::ServerKey>()), ser(&isk),);
        assert_eq!(
            ser(&ks.decompress_parts::<Option<KeySwitchingKeyMaterial>>()),
            ser(&cpk_ksk),
        );
        assert_eq!(
            ser(&ks.decompress_parts::<Option<CompressionKey>>()),
            ser(&compression),
        );
        assert_eq!(
            ser(&ks.decompress_parts::<Option<DecompressionKey>>()),
            ser(&decompression),
        );
        assert_eq!(
            ser(&ks.decompress_parts::<Option<NoiseSquashingKey>>()),
            ser(&noise_squashing),
        );
        assert_eq!(
            ser(&ks.decompress_parts::<Option<NoiseSquashingCompressionKey>>()),
            ser(&ns_compression),
        );
        assert_eq!(
            ser(&ks.decompress_parts::<Option<ReRandomizationKey>>()),
            ser(&re_rand),
        );
        assert_eq!(
            ser(&ks.decompress_parts::<Option<OprfServerKey>>()),
            ser(&oprf),
        );
    }

    // Tuples fetch each element independently; verify the KMS `NoiseFloodSmall` triple and a
    // four-tuple against a full decompression.
    #[test]
    fn tuple_parts_match_full_decompress() {
        let ks = keyset();

        let (_pk, server_key) = ks.decompress().into_raw_parts();
        let (
            isk,
            _cpk_ksk,
            _compression,
            decompression,
            noise_squashing,
            _ns_comp,
            _rerand,
            oprf,
            _tag,
        ) = server_key.into_raw_parts();

        let (t_isk, t_decompk, t_snsk): (
            crate::integer::ServerKey,
            Option<DecompressionKey>,
            Option<NoiseSquashingKey>,
        ) = ks.decompress_parts();
        assert_eq!(ser(&t_isk), ser(&isk));
        assert_eq!(ser(&t_decompk), ser(&decompression));
        assert_eq!(ser(&t_snsk), ser(&noise_squashing));

        let (q_isk, q_decompk, q_snsk, q_oprf): (
            crate::integer::ServerKey,
            Option<DecompressionKey>,
            Option<NoiseSquashingKey>,
            Option<OprfServerKey>,
        ) = ks.decompress_parts();
        assert_eq!(ser(&q_isk), ser(&isk));
        assert_eq!(ser(&q_decompk), ser(&decompression));
        assert_eq!(ser(&q_snsk), ser(&noise_squashing));
        assert_eq!(ser(&q_oprf), ser(&oprf));
    }
}
