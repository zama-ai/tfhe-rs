//! Selective decompression: fetch individual parts of a [`CompressedXofKeySet`] without
//! materializing the whole server key.
//!
//! Each call rebuilds a fresh mask generator from the seed and fast-forwards (skips) past every
//! component preceding the requested one, so calls are independent and order-free.

use super::CompressedXofKeySet;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::prelude::DefaultRandomGenerator;
use crate::high_level_api::keys::expanded::ExpandedDecompressionKey;
use crate::integer::ciphertext::NoiseSquashingCompressionKey;
use crate::integer::compression_keys::{CompressionKey, DecompressionKey};
use crate::integer::key_switching_key::KeySwitchingKeyMaterial;
use crate::integer::oprf::OprfServerKey;
use crate::prelude::Tagged;
use crate::CompactPublicKey;

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

/// A key that can be selectively decompressed from a [`CompressedXofKeySet`] via
/// [`CompressedXofKeySet::decompress_parts`]. Sealed: implemented only for the key types a key
/// set can yield.
pub trait XofPart: Sized + sealed::Sealed {
    #[doc(hidden)]
    fn decompress_part(keyset: &CompressedXofKeySet) -> crate::Result<Self>;
}

impl CompressedXofKeySet {
    /// Selectively decompress only the requested part(s), skipping the rest of the key set.
    ///
    /// `T` may be a single key type, and (later) an `Option<K>` or a tuple of such. Requesting an
    /// optional component the key set does not carry is an error.
    pub fn decompress_parts<T: XofPart>(&self) -> crate::Result<T> {
        T::decompress_part(self)
    }

    /// A fresh mask generator seeded from the key set, fast-forwarded to `target`'s position by
    /// skipping every present component before it.
    fn generator_at(&self, target: Slot) -> MaskRandomGenerator<DefaultRandomGenerator> {
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
                Compute => icsk.key.key.compressed_ap_server_key.advance_generator(&mut gen),
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

impl sealed::Sealed for CompactPublicKey {}
impl XofPart for CompactPublicKey {
    fn decompress_part(keyset: &CompressedXofKeySet) -> crate::Result<Self> {
        let mut gen = keyset.generator_at(Slot::PublicKey);

        let mut public_key = keyset
            .compressed_public_key
            .decompress_with_pre_seeded_generator(&mut gen);
        // Server key tag is the source of truth, mirror `decompress()`.
        public_key
            .tag_mut()
            .set_data(keyset.compressed_server_key.tag.data());
        Ok(public_key)
    }
}

impl sealed::Sealed for CompressionKey {}
impl XofPart for CompressionKey {
    fn decompress_part(keyset: &CompressedXofKeySet) -> crate::Result<Self> {
        let mut gen = keyset.generator_at(Slot::Compression);

        let compressed = keyset
            .compressed_server_key
            .integer_key
            .compression_key
            .as_ref()
            .ok_or_else(|| crate::error!("key set has no compression key"))?;
        Ok(compressed.decompress_with_pre_seeded_generator(&mut gen))
    }
}

impl sealed::Sealed for DecompressionKey {}
impl XofPart for DecompressionKey {
    fn decompress_part(keyset: &CompressedXofKeySet) -> crate::Result<Self> {
        let mut gen = keyset.generator_at(Slot::Decompression);

        let compressed = keyset
            .compressed_server_key
            .integer_key
            .decompression_key
            .as_ref()
            .ok_or_else(|| crate::error!("key set has no decompression key"))?;

        // Fourier conversion, mirroring `IntegerExpandedServerKey::convert_to_cpu`.
        let ExpandedDecompressionKey { bsk, lwe_per_glwe } =
            compressed.decompress_with_pre_seeded_generator(&mut gen);
        let bsk = bsk.into_fourier();
        Ok(DecompressionKey::from_raw_parts(
            crate::shortint::list_compression::DecompressionKey { bsk, lwe_per_glwe },
        ))
    }
}

impl sealed::Sealed for KeySwitchingKeyMaterial {}
impl XofPart for KeySwitchingKeyMaterial {
    fn decompress_part(keyset: &CompressedXofKeySet) -> crate::Result<Self> {
        let mut gen = keyset.generator_at(Slot::CpkKsk);

        let compressed = keyset
            .compressed_server_key
            .integer_key
            .cpk_key_switching_key_material
            .as_ref()
            .ok_or_else(|| crate::error!("key set has no compact public key switching material"))?;
        Ok(compressed.decompress_with_pre_seeded_generator(&mut gen))
    }
}

impl sealed::Sealed for NoiseSquashingCompressionKey {}
impl XofPart for NoiseSquashingCompressionKey {
    fn decompress_part(keyset: &CompressedXofKeySet) -> crate::Result<Self> {
        let mut gen = keyset.generator_at(Slot::NsCompression);

        let compressed = keyset
            .compressed_server_key
            .integer_key
            .noise_squashing_compression_key
            .as_ref()
            .ok_or_else(|| crate::error!("key set has no noise squashing compression key"))?;
        Ok(compressed.decompress_with_pre_seeded_generator(&mut gen))
    }
}

impl sealed::Sealed for OprfServerKey {}
impl XofPart for OprfServerKey {
    fn decompress_part(keyset: &CompressedXofKeySet) -> crate::Result<Self> {
        let mut gen = keyset.generator_at(Slot::Oprf);

        let compressed = keyset
            .compressed_server_key
            .integer_key
            .oprf_key
            .as_ref()
            .ok_or_else(|| crate::error!("key set has no oprf key"))?;
        Ok(compressed
            .decompress_with_pre_seeded_generator(&mut gen)
            .to_fourier())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_crypto::prelude::NormalizedHammingWeightBound;
    use crate::shortint::parameters::test_params::TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
    use crate::Tag;

    fn ser<T: serde::Serialize>(value: &T) -> Vec<u8> {
        bincode::serialize(value).unwrap()
    }

    /// Each single-component fetch must byte-match the corresponding piece of a full
    /// `decompress().into_raw_parts()`.
    #[test]
    fn single_parts_match_full_decompress() {
        let config = TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128.into();
        let (_cks, ks) = CompressedXofKeySet::generate(
            config,
            vec![9u8; 32],
            128,
            NormalizedHammingWeightBound::new(0.8).unwrap(),
            Tag::default(),
        )
        .unwrap();

        let (public_key, server_key) = ks.decompress().into_raw_parts();
        let (_isk, cpk_ksk, compression, decompression, _snsk, ns_compression, _rerand, oprf, _tag) =
            server_key.into_raw_parts();

        assert_eq!(
            ser(&ks.decompress_parts::<CompactPublicKey>().unwrap()),
            ser(&public_key),
            "public key",
        );
        assert_eq!(
            ser(&ks.decompress_parts::<CompressionKey>().unwrap()),
            ser(&compression.unwrap()),
            "compression key",
        );
        assert_eq!(
            ser(&ks.decompress_parts::<DecompressionKey>().unwrap()),
            ser(&decompression.unwrap()),
            "decompression key",
        );
        assert_eq!(
            ser(&ks.decompress_parts::<KeySwitchingKeyMaterial>().unwrap()),
            ser(&cpk_ksk.unwrap()),
            "cpk key switching material",
        );
        assert_eq!(
            ser(&ks.decompress_parts::<NoiseSquashingCompressionKey>().unwrap()),
            ser(&ns_compression.unwrap()),
            "noise squashing compression key",
        );
        assert_eq!(
            ser(&ks.decompress_parts::<OprfServerKey>().unwrap()),
            ser(&oprf.unwrap()),
            "oprf key",
        );
    }
}
