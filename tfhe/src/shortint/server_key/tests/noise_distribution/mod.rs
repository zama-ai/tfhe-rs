pub(crate) mod br_dp_ks_ms;
pub(crate) mod br_rerand_dp_ks_ms;
pub(crate) mod cpk_ks_ms;
pub(crate) mod dp_ks_ms;
pub(crate) mod dp_ks_pbs128_packingks;
pub(crate) mod utils;

pub fn should_use_single_key_debug() -> bool {
    static SINGLE_KEY_DEBUG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    *SINGLE_KEY_DEBUG.get_or_init(|| {
        std::env::var("TFHE_RS_TESTS_NOISE_MEASUREMENT_USE_SINGLE_KEY_DEBUG").is_ok_and(|val| {
            let val = val.parse::<u32>();
            val.is_ok_and(|val| val != 0)
        })
    })
}

pub fn should_run_short_pfail_tests_debug() -> bool {
    static SHORT_PFAIL_TESTS_DEBUG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    *SHORT_PFAIL_TESTS_DEBUG.get_or_init(|| {
        std::env::var("TFHE_RS_TESTS_NOISE_MEASUREMENT_SHORT_PFAIL_TESTS_DEBUG").is_ok_and(|val| {
            let val = val.parse::<u32>();
            val.is_ok_and(|val| val != 0)
        })
    })
}

pub fn should_load_dkg_keys() -> Option<std::path::PathBuf> {
    static USE_DKG_KEYS: std::sync::OnceLock<Option<std::path::PathBuf>> =
        std::sync::OnceLock::new();

    USE_DKG_KEYS
        .get_or_init(|| {
            std::env::var("TFHE_RS_TESTS_NOISE_MEASUREMENT_USE_DKG_KEYS")
                .map(|val| {
                    let mut res = std::path::PathBuf::new();
                    res.push(val);

                    res
                })
                .ok()
        })
        .clone()
}
