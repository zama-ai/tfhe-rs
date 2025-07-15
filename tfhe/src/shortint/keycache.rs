use crate::keycache::*;
use crate::named_params_impl;
use crate::shortint::parameters::key_switching::*;
use crate::shortint::parameters::multi_bit::*;
use crate::shortint::parameters::parameters_compact_pk::*;
use crate::shortint::parameters::parameters_wopbs::*;
use crate::shortint::parameters::parameters_wopbs_message_carry::*;
use crate::shortint::parameters::parameters_wopbs_prime_moduli::*;
use crate::shortint::parameters::*;
use crate::shortint::wopbs::WopbsKey;
use crate::shortint::{ClientKey, KeySwitchingKey, ServerKey};
use lazy_static::*;
use serde::{Deserialize, Serialize};

named_params_impl!( ShortintParameterSet =>
    PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    PARAM_MESSAGE_2_CARRY_0_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    PARAM_MESSAGE_3_CARRY_0_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    PARAM_MESSAGE_4_CARRY_0_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_KS_PBS,
    PARAM_MESSAGE_8_CARRY_0_KS_PBS,
    // Small
    PARAM_MESSAGE_1_CARRY_1_PBS_KS,
    PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    PARAM_MESSAGE_3_CARRY_3_PBS_KS,
    PARAM_MESSAGE_4_CARRY_4_PBS_KS,
    // MultiBit Group 2
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    // MultiBit Group 3
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
    // CPK
    PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS,
    // CPK SMALL
    PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_PBS_KS,
    PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_PBS_KS,
    // Wopbs
    WOPBS_PARAM_MESSAGE_1_NORM2_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_NORM2_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_NORM2_6_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_NORM2_8_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_NORM2_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_NORM2_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_NORM2_6_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_NORM2_8_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_NORM2_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_NORM2_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_NORM2_6_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_NORM2_8_KS_PBS,
    WOPBS_PARAM_MESSAGE_4_NORM2_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_4_NORM2_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_4_NORM2_6_KS_PBS,
    WOPBS_PARAM_MESSAGE_4_NORM2_8_KS_PBS,
    WOPBS_PARAM_MESSAGE_5_NORM2_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_5_NORM2_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_5_NORM2_6_KS_PBS,
    WOPBS_PARAM_MESSAGE_5_NORM2_8_KS_PBS,
    WOPBS_PARAM_MESSAGE_6_NORM2_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_6_NORM2_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_6_NORM2_6_KS_PBS,
    WOPBS_PARAM_MESSAGE_6_NORM2_8_KS_PBS,
    WOPBS_PARAM_MESSAGE_7_NORM2_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_7_NORM2_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_7_NORM2_6_KS_PBS,
    WOPBS_PARAM_MESSAGE_7_NORM2_8_KS_PBS,
    WOPBS_PARAM_MESSAGE_8_NORM2_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_8_NORM2_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_8_NORM2_6_KS_PBS,
    //WOPBS_PARAM_MESSAGE_8_NORM2_5_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    WOPBS_PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_CARRY_0_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    WOPBS_PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_CARRY_0_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    WOPBS_PARAM_MESSAGE_4_CARRY_0_KS_PBS,
    WOPBS_PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    WOPBS_PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    WOPBS_PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    WOPBS_PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    WOPBS_PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    WOPBS_PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    WOPBS_PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    WOPBS_PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    WOPBS_PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    WOPBS_PARAM_MESSAGE_7_CARRY_1_KS_PBS,
    WOPBS_PARAM_MESSAGE_8_CARRY_0_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_2_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_3_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_4_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_5_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_6_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_7_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_8_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_2_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_3_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_4_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_5_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_6_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_7_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_3_NORM2_8_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_2_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_3_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_4_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_5_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_6_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_7_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_4_NORM2_8_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_2_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_3_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_4_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_5_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_6_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_7_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_5_NORM2_8_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_2_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_3_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_4_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_5_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_6_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_7_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_6_NORM2_8_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_2_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_3_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_4_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_5_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_6_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_7_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_7_NORM2_8_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_2_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_3_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_4_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_5_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_6_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_7_KS_PBS,
    WOPBS_PRIME_PARAM_MESSAGE_8_NORM2_8_KS_PBS,
    PARAM_4_BITS_5_BLOCKS,
);

impl NamedParam for ClassicPBSParameters {
    fn name(&self) -> String {
        PBSParameters::from(*self).name()
    }
}

impl NamedParam for MultiBitPBSParameters {
    fn name(&self) -> String {
        PBSParameters::from(*self).name()
    }
}

impl NamedParam for PBSParameters {
    fn name(&self) -> String {
        ShortintParameterSet::from(*self).name()
    }
}

impl NamedParam for WopbsParameters {
    fn name(&self) -> String {
        ShortintParameterSet::from(*self).name()
    }
}

impl NamedParam for ShortintKeySwitchingParameters {
    fn name(&self) -> String {
        named_params_impl!(expose PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS);
        named_params_impl!(
            {
                *self;
                Self
            } == (PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS)
        );

        format!(
            "PARAM_KEYSWITCH_CUSTOM_KS_LEVEL_{}_KS_BASE_LOG_{}",
            self.ks_level.0, self.ks_base_log.0
        )
    }
}

impl From<PBSParameters> for (ClientKey, ServerKey) {
    fn from(param: PBSParameters) -> Self {
        let param_set = ShortintParameterSet::from(param);
        param_set.into()
    }
}

impl From<ShortintParameterSet> for (ClientKey, ServerKey) {
    fn from(param: ShortintParameterSet) -> Self {
        let cks = ClientKey::new(param);
        let sks = ServerKey::new(&cks);
        (cks, sks)
    }
}

pub struct Keycache {
    inner: ImplKeyCache<PBSParameters, (ClientKey, ServerKey), FileStorage>,
}

impl Default for Keycache {
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new(
                "../keys/shortint/client_server".to_string(),
            )),
        }
    }
}

pub struct SharedKey {
    inner: GenericSharedKey<(ClientKey, ServerKey)>,
}

pub struct SharedWopbsKey {
    inner: GenericSharedKey<(ClientKey, ServerKey)>,
    wopbs: GenericSharedKey<WopbsKey>,
}

pub struct SharedKeySwitchingKey {
    inner_1: GenericSharedKey<(ClientKey, ServerKey)>,
    inner_2: GenericSharedKey<(ClientKey, ServerKey)>,
    ksk: GenericSharedKey<KeySwitchingKey>,
}

impl SharedKey {
    pub fn client_key(&self) -> &ClientKey {
        &self.inner.0
    }
    pub fn server_key(&self) -> &ServerKey {
        &self.inner.1
    }
}

impl SharedWopbsKey {
    pub fn client_key(&self) -> &ClientKey {
        &self.inner.0
    }
    pub fn server_key(&self) -> &ServerKey {
        &self.inner.1
    }
    pub fn wopbs_key(&self) -> &WopbsKey {
        &self.wopbs
    }
}

impl SharedKeySwitchingKey {
    pub fn client_key_1(&self) -> &ClientKey {
        &self.inner_1.0
    }
    pub fn server_key_1(&self) -> &ServerKey {
        &self.inner_1.1
    }
    pub fn client_key_2(&self) -> &ClientKey {
        &self.inner_2.0
    }
    pub fn server_key_2(&self) -> &ServerKey {
        &self.inner_2.1
    }
    pub fn key_switching_key(&self) -> &KeySwitchingKey {
        &self.ksk
    }
}

impl Keycache {
    pub fn get_from_param<P>(&self, param: P) -> SharedKey
    where
        P: Into<PBSParameters>,
    {
        SharedKey {
            inner: self.inner.get(param.into()),
        }
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WopbsParamPair(pub PBSParameters, pub WopbsParameters);

impl<P> From<(P, WopbsParameters)> for WopbsParamPair
where
    P: Into<PBSParameters>,
{
    fn from(tuple: (P, WopbsParameters)) -> Self {
        Self(tuple.0.into(), tuple.1)
    }
}

impl NamedParam for WopbsParamPair {
    fn name(&self) -> String {
        self.1.name()
    }
}

/// The KeyCache struct for shortint.
///
/// You should not create an instance yourself,
/// but rather use the global variable defined: [KEY_CACHE_WOPBS]
pub struct KeycacheWopbsV0 {
    inner: ImplKeyCache<WopbsParamPair, WopbsKey, FileStorage>,
}

impl Default for KeycacheWopbsV0 {
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new("../keys/shortint/wopbs_v0".to_string())),
        }
    }
}

impl KeycacheWopbsV0 {
    pub fn get_from_param<T: Into<WopbsParamPair>>(&self, params: T) -> SharedWopbsKey {
        let params = params.into();
        let key = KEY_CACHE.get_from_param(params.0);
        let wk = self.inner.get_with_closure(params, &mut |_| {
            WopbsKey::new_wopbs_key(&key.inner.0, &key.inner.1, &params.1)
        });
        SharedWopbsKey {
            inner: key.inner,
            wopbs: wk,
        }
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeySwitchingKeyParams(
    pub PBSParameters,
    pub PBSParameters,
    pub ShortintKeySwitchingParameters,
);

impl<P> From<(P, P, ShortintKeySwitchingParameters)> for KeySwitchingKeyParams
where
    P: Into<PBSParameters>,
{
    fn from(tuple: (P, P, ShortintKeySwitchingParameters)) -> Self {
        Self(tuple.0.into(), tuple.1.into(), tuple.2)
    }
}

impl NamedParam for KeySwitchingKeyParams {
    fn name(&self) -> String {
        format!("{}__{}__{}", self.0.name(), self.1.name(), self.2.name())
    }
}

/// The KeyCache struct for shortint.
///
/// You should not create an instance yourself,
/// but rather use the global variable defined: [KEY_CACHE_KSK]
pub struct KeycacheKeySwitchingKey {
    inner: ImplKeyCache<KeySwitchingKeyParams, KeySwitchingKey, FileStorage>,
}

impl Default for KeycacheKeySwitchingKey {
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new("../keys/shortint/ksk".to_string())),
        }
    }
}

impl KeycacheKeySwitchingKey {
    pub fn get_from_param<T: Into<KeySwitchingKeyParams>>(
        &self,
        params: T,
    ) -> SharedKeySwitchingKey {
        let params = params.into();
        let key_1 = KEY_CACHE.get_from_param(params.0);
        let key_2 = KEY_CACHE.get_from_param(params.1);
        let ksk = self.inner.get_with_closure(params, &mut |_| {
            KeySwitchingKey::new(
                (key_1.client_key(), key_1.server_key()),
                (key_2.client_key(), key_2.server_key()),
                params.2,
            )
        });
        SharedKeySwitchingKey {
            inner_1: key_1.inner,
            inner_2: key_2.inner,
            ksk,
        }
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

lazy_static! {
    pub static ref KEY_CACHE: Keycache = Keycache::default();
    pub static ref KEY_CACHE_WOPBS: KeycacheWopbsV0 = KeycacheWopbsV0::default();
    pub static ref KEY_CACHE_KSK: KeycacheKeySwitchingKey = KeycacheKeySwitchingKey::default();
}
