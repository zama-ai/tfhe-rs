#[cfg(feature = "gpu")]
use crate::core_crypto::algorithms::test::NoiseSquashingTestParams;
use crate::core_crypto::algorithms::test::{
    lwe_multi_bit_programmable_bootstrapping, lwe_packing_keyswitch,
    lwe_programmable_bootstrapping, ClassicBootstrapKeys, ClassicTestParams, FftBootstrapKeys,
    FftTestParams, FftWopPbsKeys, FftWopPbsTestParams, MultiBitBootstrapKeys, MultiBitTestParams,
    PackingKeySwitchKeys, PackingKeySwitchTestParams, TestResources,
};
use crate::core_crypto::prelude::{CastFrom, CastInto, UnsignedTorus};
use crate::keycache::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::LazyLock;
pub struct KeyCacheCoreImpl<P, K>
where
    P: Copy + NamedParam + DeserializeOwned + Serialize + PartialEq,
    K: DeserializeOwned + Serialize,
{
    inner: ImplKeyCache<P, K, FileStorage>,
}

impl<
        P: Copy + NamedParam + DeserializeOwned + Serialize + PartialEq,
        K: DeserializeOwned + Serialize,
    > Default for KeyCacheCoreImpl<P, K>
{
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new(
                "../keys/core_crypto/bootstrap".to_string(),
            )),
        }
    }
}

impl<P, K> KeyCacheCoreImpl<P, K>
where
    P: Copy + NamedParam + DeserializeOwned + Serialize + PartialEq,
    K: DeserializeOwned + Serialize + Clone + GenerateKeyFromParams<P>,
{
    pub fn get_key(&self, params: P) -> K {
        (*self.inner.get(params)).clone()
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

#[derive(Default)]
pub struct KeyCache {
    u32_multi_bit: KeyCacheCoreImpl<MultiBitTestParams<u32>, MultiBitBootstrapKeys<u32>>,
    u64_multi_bit: KeyCacheCoreImpl<MultiBitTestParams<u64>, MultiBitBootstrapKeys<u64>>,
    u32_classic: KeyCacheCoreImpl<ClassicTestParams<u32>, ClassicBootstrapKeys<u32>>,
    u64_classic: KeyCacheCoreImpl<ClassicTestParams<u64>, ClassicBootstrapKeys<u64>>,
    u128_classic: KeyCacheCoreImpl<ClassicTestParams<u128>, ClassicBootstrapKeys<u128>>,
    u32_fft: KeyCacheCoreImpl<FftTestParams<u32>, FftBootstrapKeys<u32>>,
    u64_fft: KeyCacheCoreImpl<FftTestParams<u64>, FftBootstrapKeys<u64>>,
    u128_fft: KeyCacheCoreImpl<FftTestParams<u128>, FftBootstrapKeys<u128>>,
    u64_fft_wopbs: KeyCacheCoreImpl<FftWopPbsTestParams<u64>, FftWopPbsKeys<u64>>,
    u32_pksk: KeyCacheCoreImpl<PackingKeySwitchTestParams<u32>, PackingKeySwitchKeys<u32>>,
    u64_pksk: KeyCacheCoreImpl<PackingKeySwitchTestParams<u64>, PackingKeySwitchKeys<u64>>,
    #[cfg(feature = "gpu")]
    u128_noise_squashing: KeyCacheCoreImpl<NoiseSquashingTestParams<u128>, FftBootstrapKeys<u128>>,
}

impl KeyCache {
    pub fn get_key<P>(&self, params: P) -> P::Keys
    where
        P: KeyCacheAccess,
    {
        P::access(self).get_key(params)
    }

    pub fn clear_in_memory_cache<P>(&self)
    where
        P: KeyCacheAccess,
    {
        P::access(self).clear_in_memory_cache();
    }
}

pub trait KeyCacheAccess: Serialize + DeserializeOwned + Copy + PartialEq + NamedParam {
    type Keys: DeserializeOwned + Serialize + Clone + GenerateKeyFromParams<Self>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys>;
}

impl KeyCacheAccess for MultiBitTestParams<u32> {
    type Keys = MultiBitBootstrapKeys<u32>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u32_multi_bit
    }
}

impl KeyCacheAccess for MultiBitTestParams<u64> {
    type Keys = MultiBitBootstrapKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_multi_bit
    }
}

impl KeyCacheAccess for ClassicTestParams<u32> {
    type Keys = ClassicBootstrapKeys<u32>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u32_classic
    }
}

impl KeyCacheAccess for ClassicTestParams<u64> {
    type Keys = ClassicBootstrapKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_classic
    }
}

impl KeyCacheAccess for ClassicTestParams<u128> {
    type Keys = ClassicBootstrapKeys<u128>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u128_classic
    }
}

impl KeyCacheAccess for FftTestParams<u32> {
    type Keys = FftBootstrapKeys<u32>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u32_fft
    }
}

impl KeyCacheAccess for FftTestParams<u64> {
    type Keys = FftBootstrapKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_fft
    }
}

impl KeyCacheAccess for FftTestParams<u128> {
    type Keys = FftBootstrapKeys<u128>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u128_fft
    }
}

impl KeyCacheAccess for FftWopPbsTestParams<u64> {
    type Keys = FftWopPbsKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_fft_wopbs
    }
}

impl KeyCacheAccess for PackingKeySwitchTestParams<u32> {
    type Keys = PackingKeySwitchKeys<u32>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u32_pksk
    }
}

impl KeyCacheAccess for PackingKeySwitchTestParams<u64> {
    type Keys = PackingKeySwitchKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_pksk
    }
}
#[cfg(feature = "gpu")]
impl KeyCacheAccess for NoiseSquashingTestParams<u128> {
    type Keys = FftBootstrapKeys<u128>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u128_noise_squashing
    }
}

impl<Scalar> GenerateKeyFromParams<ClassicTestParams<Scalar>> for ClassicBootstrapKeys<Scalar>
where
    Scalar: UnsignedTorus
        + Sync
        + Send
        + CastFrom<usize>
        + CastInto<usize>
        + Serialize
        + DeserializeOwned,
{
    fn generate_key_from_params(params: ClassicTestParams<Scalar>) -> Self {
        lwe_programmable_bootstrapping::generate_keys(params, &mut TestResources::new())
    }
}

impl<Scalar> GenerateKeyFromParams<MultiBitTestParams<Scalar>> for MultiBitBootstrapKeys<Scalar>
where
    Scalar: UnsignedTorus
        + Sync
        + Send
        + CastFrom<usize>
        + CastInto<usize>
        + Serialize
        + DeserializeOwned,
{
    fn generate_key_from_params(params: MultiBitTestParams<Scalar>) -> Self {
        lwe_multi_bit_programmable_bootstrapping::generate_keys(params, &mut TestResources::new())
    }
}

impl<Scalar> GenerateKeyFromParams<FftTestParams<Scalar>> for FftBootstrapKeys<Scalar>
where
    Scalar: UnsignedTorus
        + Sync
        + Send
        + CastFrom<usize>
        + CastInto<usize>
        + Serialize
        + DeserializeOwned,
{
    fn generate_key_from_params(params: FftTestParams<Scalar>) -> Self {
        crate::core_crypto::fft_impl::common::tests::generate_keys(
            params,
            &mut TestResources::new(),
        )
    }
}

impl<Scalar> GenerateKeyFromParams<FftWopPbsTestParams<Scalar>> for FftWopPbsKeys<Scalar>
where
    Scalar: UnsignedTorus
        + Sync
        + Send
        + CastFrom<usize>
        + CastInto<usize>
        + Serialize
        + DeserializeOwned,
{
    fn generate_key_from_params(params: FftWopPbsTestParams<Scalar>) -> Self {
        crate::core_crypto::fft_impl::fft64::crypto::wop_pbs::tests::generate_keys(
            params,
            &mut TestResources::new(),
        )
    }
}

impl<Scalar> GenerateKeyFromParams<PackingKeySwitchTestParams<Scalar>>
    for PackingKeySwitchKeys<Scalar>
where
    Scalar: UnsignedTorus + Sync + Send + Serialize + DeserializeOwned,
{
    fn generate_key_from_params(params: PackingKeySwitchTestParams<Scalar>) -> Self {
        lwe_packing_keyswitch::generate_keys(params, &mut TestResources::new())
    }
}

#[cfg(feature = "gpu")]
impl<Scalar> GenerateKeyFromParams<NoiseSquashingTestParams<Scalar>> for FftBootstrapKeys<Scalar>
where
    Scalar: UnsignedTorus
        + Sync
        + Send
        + CastFrom<usize>
        + CastFrom<u64>
        + CastInto<usize>
        + Serialize
        + DeserializeOwned,
{
    fn generate_key_from_params(params: NoiseSquashingTestParams<Scalar>) -> Self {
        crate::core_crypto::gpu::algorithms::test::lwe_programmable_bootstrapping_128::generate_keys(
            params,
            &mut TestResources::new(),
        )
    }
}

pub static KEY_CACHE: LazyLock<KeyCache> = LazyLock::new(KeyCache::default);

#[cfg(feature = "internal-keycache")]
#[test]
pub fn generate_keys() {
    use crate::core_crypto::algorithms::test::{
        DUMMY_31_U32, DUMMY_NATIVE_U32, FFT128_U128_PARAMS, FFT_U128_PARAMS, FFT_U32_PARAMS,
        FFT_U64_PARAMS, FFT_WOPBS_N1024_PARAMS, FFT_WOPBS_N2048_PARAMS, FFT_WOPBS_N512_PARAMS,
        FFT_WOPBS_PARAMS, MULTI_BIT_2_2_2_CUSTOM_MOD_PARAMS, MULTI_BIT_2_2_2_PARAMS,
        MULTI_BIT_2_2_3_CUSTOM_MOD_PARAMS, MULTI_BIT_2_2_3_PARAMS, TEST_PARAMS_3_BITS_63_U64,
        TEST_PARAMS_4_BITS_NATIVE_U64,
    };

    fn generate_and_store<P>(params: P)
    where
        P: KeyCacheAccess,
    {
        println!("Generating : {}", params.name());

        let start = std::time::Instant::now();

        let _ = KEY_CACHE.get_key(params);

        let stop = start.elapsed().as_secs();

        println!("Generation took {stop} seconds");

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE.clear_in_memory_cache::<P>();
    }

    println!("Generating keys for core_crypto");

    for param in [DUMMY_31_U32, DUMMY_NATIVE_U32] {
        generate_and_store(param);
    }

    for param in [
        MULTI_BIT_2_2_2_PARAMS,
        MULTI_BIT_2_2_3_PARAMS,
        MULTI_BIT_2_2_2_CUSTOM_MOD_PARAMS,
        MULTI_BIT_2_2_3_CUSTOM_MOD_PARAMS,
    ] {
        generate_and_store(param);
    }

    for param in [TEST_PARAMS_4_BITS_NATIVE_U64, TEST_PARAMS_3_BITS_63_U64] {
        generate_and_store(param);
    }

    generate_and_store(FFT_U32_PARAMS);
    generate_and_store(FFT_U64_PARAMS);
    generate_and_store(FFT_U128_PARAMS);
    generate_and_store(FFT128_U128_PARAMS);

    for param in [
        FFT_WOPBS_PARAMS,
        FFT_WOPBS_N512_PARAMS,
        FFT_WOPBS_N1024_PARAMS,
        FFT_WOPBS_N2048_PARAMS,
    ] {
        generate_and_store(param);
    }
}
