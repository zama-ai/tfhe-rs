use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::seeders::{AesVariant, Seed, SeedKind, XofSeed};

#[derive(VersionsDispatch)]
pub enum XofSeedVersions {
    V0(XofSeed),
}

#[derive(VersionsDispatch)]
pub enum SeedVersions {
    V0(Seed),
}

#[derive(VersionsDispatch)]
pub enum AesVariantVersions {
    V0(AesVariant),
}

#[derive(Version)]
pub enum SeedKindV0 {
    Ctr(Seed),
    Xof(XofSeed),
}

impl Upgrade<SeedKind> for SeedKindV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SeedKind, Self::Error> {
        Ok(match self {
            Self::Ctr(seed) => SeedKind::Ctr(seed),
            // Everything serialized by tfhe-rs 1.6 and earlier was derived by `xof_init_128`
            Self::Xof(seed) => SeedKind::xof_aes128(seed),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum SeedKindVersions {
    V0(SeedKindV0),
    V1(SeedKind),
}

#[cfg(test)]
mod test {
    use crate::seeders::{AesVariant, SeedKind, XofSeed};
    use bincode::Options;
    use tfhe_versionable::{Unversionize, VersionizeOwned};

    fn bincode_options() -> impl bincode::Options {
        bincode::DefaultOptions::new().with_fixint_encoding()
    }

    #[test]
    fn test_unversionize_legacy_xof_bincode_is_aes128() {
        /// Bincode encoding of `SeedKindVersions::V0(SeedKind::Xof(XofSeed::new_u128(1,
        /// b"abcdefgh")))` as written by tfhe-csprng 0.9 and earlier.
        const LEGACY_XOF_BINCODE: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // SeedKindVersions::V0
            0x01, 0x00, 0x00, 0x00, // SeedKind::Xof, the second variant
            0x00, 0x00, 0x00, 0x00, // XofSeedVersions::V0
            0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data length: 8 + 16 = 24
            b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', // domain separator
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // seed: 1u128, little endian
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let seed = XofSeed::new_u128(1u128, *b"abcdefgh");

        let deserialized: <SeedKind as VersionizeOwned>::VersionedOwned = bincode_options()
            .deserialize_from(LEGACY_XOF_BINCODE)
            .expect("legacy bincode SeedKind must still deserialize");
        let seed_kind = SeedKind::unversionize(deserialized).expect("upgrade must succeed");

        assert_eq!(
            seed_kind,
            SeedKind::Xof {
                seed,
                aes: AesVariant::Aes128,
            }
        );
    }
}
