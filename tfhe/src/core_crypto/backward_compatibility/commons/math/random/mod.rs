use std::convert::Infallible;
use tfhe_versionable::{Upgrade, VersionsDispatch};

use crate::core_crypto::commons::math::random::*;
use crate::core_crypto::prelude::{FloatingPoint, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum TUniformVersions<T: UnsignedInteger> {
    V0(TUniform<T>),
}

#[derive(VersionsDispatch)]
pub enum GaussianVersions<T: FloatingPoint> {
    V0(Gaussian<T>),
}

#[derive(VersionsDispatch)]
pub enum DynamicDistributionVersions<T: UnsignedInteger> {
    V0(DynamicDistribution<T>),
}

// Between V0 and V1 one of the changes is that the Seed type
// from tfhe_csprng now implements versionize, so the manual impl
// that was done in tfhe::core_crypto is no longer necessary.
//
// However to keep structural compatibility (e.g CBOR format) we need
// this boiler plate
mod compression_seed_v0 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::{UnversionizeError, Version};

    use tfhe_csprng::seeders::Seed;
    // See https://serde.rs/remote-derive.html
    // Serde calls this the definition of the remote type. It is just a copy of the remote data
    // structure. The `remote` attribute gives the path to the actual type we intend to derive code
    // for. This avoids having to introduce serde in tfhe-csprng
    #[derive(Serialize, Deserialize)]
    #[serde(remote = "Seed")]
    pub(crate) struct SeedSerdeDef(pub u128);

    #[derive(Deserialize, Serialize)]
    pub struct CompressionSeedV0Proxy {
        #[serde(with = "SeedSerdeDef")]
        pub seed: Seed,
    }

    impl From<CompressionSeedV0> for CompressionSeedV0Proxy {
        fn from(value: CompressionSeedV0) -> Self {
            let CompressionSeedV0 { seed } = value;
            Self { seed }
        }
    }

    impl<'a> From<&'a CompressionSeedV0> for CompressionSeedV0Proxy {
        fn from(value: &'a CompressionSeedV0) -> Self {
            let CompressionSeedV0 { seed } = value;
            Self { seed: *seed }
        }
    }

    impl TryInto<CompressionSeedV0> for CompressionSeedV0Proxy {
        type Error = UnversionizeError;

        fn try_into(self) -> Result<CompressionSeedV0, Self::Error> {
            let Self { seed } = self;
            Ok(CompressionSeedV0 { seed })
        }
    }

    pub struct CompressionSeedV0 {
        pub seed: Seed,
    }

    impl Version for CompressionSeedV0 {
        type Ref<'vers>
            = CompressionSeedV0Proxy
        where
            Self: 'vers;

        type Owned = CompressionSeedV0Proxy;
    }
}
use compression_seed_v0::CompressionSeedV0;

impl Upgrade<CompressionSeed> for CompressionSeedV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressionSeed, Self::Error> {
        let Self { seed } = self;
        Ok(CompressionSeed { seed })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressionSeedVersions {
    V0(CompressionSeedV0),
    V1(CompressionSeed),
}
