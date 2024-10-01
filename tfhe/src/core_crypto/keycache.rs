use crate::core_crypto::algorithms::test::{
    ClassicBootstrapKeys, ClassicTestParams, FftBootstrapKeys, FftTestParams, FftWopPbsKeys,
    FftWopPbsTestParams, MultiBitBootstrapKeys, MultiBitTestParams, PackingKeySwitchKeys,
    PackingKeySwitchTestParams,
};
use crate::keycache::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
#[cfg(feature = "internal-keycache")]
use std::fmt::Debug;
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
    K: DeserializeOwned + Serialize + Clone,
{
    pub fn get_key_with_closure<C>(&self, params: P, mut c: C) -> K
    where
        C: FnMut(P) -> K,
    {
        (*self.inner.get_with_closure(params, &mut c)).clone()
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

#[derive(Default)]
pub struct KeyCache {
    u32_multi_bit_cache: KeyCacheCoreImpl<MultiBitTestParams<u32>, MultiBitBootstrapKeys<u32>>,
    u64_multi_bit_cache: KeyCacheCoreImpl<MultiBitTestParams<u64>, MultiBitBootstrapKeys<u64>>,
    u32_classic_cache: KeyCacheCoreImpl<ClassicTestParams<u32>, ClassicBootstrapKeys<u32>>,
    u64_classic_cache: KeyCacheCoreImpl<ClassicTestParams<u64>, ClassicBootstrapKeys<u64>>,
    u128_classic_cache: KeyCacheCoreImpl<ClassicTestParams<u128>, ClassicBootstrapKeys<u128>>,
    u32_fft_cache: KeyCacheCoreImpl<FftTestParams<u32>, FftBootstrapKeys<u32>>,
    u64_fft_cache: KeyCacheCoreImpl<FftTestParams<u64>, FftBootstrapKeys<u64>>,
    u128_fft_cache: KeyCacheCoreImpl<FftTestParams<u128>, FftBootstrapKeys<u128>>,
    u64_fft_wopbs_cache: KeyCacheCoreImpl<FftWopPbsTestParams<u64>, FftWopPbsKeys<u64>>,
    u32_pksk_cache: KeyCacheCoreImpl<PackingKeySwitchTestParams<u32>, PackingKeySwitchKeys<u32>>,
    u64_pksk_cache: KeyCacheCoreImpl<PackingKeySwitchTestParams<u64>, PackingKeySwitchKeys<u64>>,
}

impl KeyCache {
    pub fn get_key_with_closure<C, P, K>(&self, params: P, c: C) -> K
    where
        C: FnMut(P) -> K,
        P: KeyCacheAccess<Keys = K> + Serialize + DeserializeOwned + Copy + PartialEq + NamedParam,
        K: DeserializeOwned + Serialize + Clone,
    {
        P::access(self).get_key_with_closure(params, c)
    }

    pub fn clear_in_memory_cache<P, K>(&self)
    where
        P: KeyCacheAccess<Keys = K> + Serialize + DeserializeOwned + Copy + PartialEq + NamedParam,
        K: DeserializeOwned + Serialize + Clone,
    {
        P::access(self).clear_in_memory_cache();
    }
}

pub trait KeyCacheAccess: Serialize + DeserializeOwned + Copy + PartialEq + NamedParam {
    type Keys: DeserializeOwned + Serialize;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys>;
}

impl KeyCacheAccess for MultiBitTestParams<u32> {
    type Keys = MultiBitBootstrapKeys<u32>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u32_multi_bit_cache
    }
}

impl KeyCacheAccess for MultiBitTestParams<u64> {
    type Keys = MultiBitBootstrapKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_multi_bit_cache
    }
}

impl KeyCacheAccess for ClassicTestParams<u32> {
    type Keys = ClassicBootstrapKeys<u32>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u32_classic_cache
    }
}

impl KeyCacheAccess for ClassicTestParams<u64> {
    type Keys = ClassicBootstrapKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_classic_cache
    }
}

impl KeyCacheAccess for ClassicTestParams<u128> {
    type Keys = ClassicBootstrapKeys<u128>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u128_classic_cache
    }
}

impl KeyCacheAccess for FftTestParams<u32> {
    type Keys = FftBootstrapKeys<u32>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u32_fft_cache
    }
}

impl KeyCacheAccess for FftTestParams<u64> {
    type Keys = FftBootstrapKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_fft_cache
    }
}

impl KeyCacheAccess for FftTestParams<u128> {
    type Keys = FftBootstrapKeys<u128>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u128_fft_cache
    }
}

impl KeyCacheAccess for FftWopPbsTestParams<u64> {
    type Keys = FftWopPbsKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_fft_wopbs_cache
    }
}

impl KeyCacheAccess for PackingKeySwitchTestParams<u32> {
    type Keys = PackingKeySwitchKeys<u32>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u32_pksk_cache
    }
}

impl KeyCacheAccess for PackingKeySwitchTestParams<u64> {
    type Keys = PackingKeySwitchKeys<u64>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        &keycache.u64_pksk_cache
    }
}

pub static KEY_CACHE: LazyLock<KeyCache> = LazyLock::new(KeyCache::default);

#[cfg(feature = "internal-keycache")]
#[test]
pub fn generate_keys() {
    use crate::core_crypto::algorithms::test::{
        lwe_multi_bit_programmable_bootstrapping, lwe_programmable_bootstrapping, TestResources,
        DUMMY_31_U32, DUMMY_NATIVE_U32, FFT128_U128_PARAMS, FFT_U128_PARAMS, FFT_U32_PARAMS,
        FFT_U64_PARAMS, FFT_WOPBS_N1024_PARAMS, FFT_WOPBS_N2048_PARAMS, FFT_WOPBS_N512_PARAMS,
        FFT_WOPBS_PARAMS, MULTI_BIT_2_2_2_CUSTOM_MOD_PARAMS, MULTI_BIT_2_2_2_PARAMS,
        MULTI_BIT_2_2_3_CUSTOM_MOD_PARAMS, MULTI_BIT_2_2_3_PARAMS, TEST_PARAMS_3_BITS_63_U64,
        TEST_PARAMS_4_BITS_NATIVE_U64,
    };
    use crate::core_crypto::fft_impl;
    use crate::core_crypto::fft_impl::fft64::crypto::wop_pbs;

    fn generate_and_store<
        P: Debug + KeyCacheAccess<Keys = K> + serde::Serialize + serde::de::DeserializeOwned,
        K: serde::de::DeserializeOwned + serde::Serialize + Clone,
    >(
        params: P,
        keygen_func: &mut dyn FnMut(P) -> K,
    ) {
        println!("Generating : {}", params.name());

        let start = std::time::Instant::now();

        let _ = KEY_CACHE.get_key_with_closure(params, keygen_func);

        let stop = start.elapsed().as_secs();

        println!("Generation took {stop} seconds");

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE.clear_in_memory_cache::<P, K>();
    }

    let mut rsc = TestResources::new();

    println!("Generating keys for core_crypto");

    let classical_u32_params = vec![DUMMY_31_U32, DUMMY_NATIVE_U32];
    for param in classical_u32_params.iter().copied() {
        let mut keys_gen = |_| lwe_programmable_bootstrapping::generate_keys(param, &mut rsc);
        generate_and_store(param, &mut keys_gen);
    }

    let multi_bit_params = [
        MULTI_BIT_2_2_2_PARAMS,
        MULTI_BIT_2_2_3_PARAMS,
        MULTI_BIT_2_2_2_CUSTOM_MOD_PARAMS,
        MULTI_BIT_2_2_3_CUSTOM_MOD_PARAMS,
    ];
    for param in multi_bit_params.iter().copied() {
        let mut keys_gen =
            |_| lwe_multi_bit_programmable_bootstrapping::generate_keys(param, &mut rsc);
        generate_and_store(param, &mut keys_gen);
    }

    let classical_u64_params = [TEST_PARAMS_4_BITS_NATIVE_U64, TEST_PARAMS_3_BITS_63_U64];
    for param in classical_u64_params.iter().copied() {
        let mut keys_gen = |_| lwe_programmable_bootstrapping::generate_keys(param, &mut rsc);
        generate_and_store(param, &mut keys_gen);
    }

    generate_and_store(FFT_U32_PARAMS, &mut |_| {
        fft_impl::common::tests::generate_keys(FFT_U32_PARAMS, &mut rsc)
    });
    generate_and_store(FFT_U64_PARAMS, &mut |_| {
        fft_impl::common::tests::generate_keys(FFT_U64_PARAMS, &mut rsc)
    });
    generate_and_store(FFT_U128_PARAMS, &mut |_| {
        fft_impl::common::tests::generate_keys(FFT_U128_PARAMS, &mut rsc)
    });

    generate_and_store(FFT128_U128_PARAMS, &mut |_| {
        fft_impl::common::tests::generate_keys(FFT128_U128_PARAMS, &mut rsc)
    });

    generate_and_store(FFT_WOPBS_PARAMS, &mut |_| {
        wop_pbs::tests::generate_keys(FFT_WOPBS_PARAMS, &mut rsc)
    });
    generate_and_store(FFT_WOPBS_N512_PARAMS, &mut |_| {
        wop_pbs::tests::generate_keys(FFT_WOPBS_N512_PARAMS, &mut rsc)
    });
    generate_and_store(FFT_WOPBS_N1024_PARAMS, &mut |_| {
        wop_pbs::tests::generate_keys(FFT_WOPBS_N1024_PARAMS, &mut rsc)
    });
    generate_and_store(FFT_WOPBS_N2048_PARAMS, &mut |_| {
        wop_pbs::tests::generate_keys(FFT_WOPBS_N2048_PARAMS, &mut rsc)
    });
}
