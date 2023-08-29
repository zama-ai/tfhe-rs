// To have clear error messages during compilation about why some piece of code may not be available
// we decided to check the features compatibility with the target configuration in this script.

use std::collections::HashMap;
use std::env;

// See https://doc.rust-lang.org/reference/conditional-compilation.html#target_arch for various
// compilation configuration

// Can be easily extended if needed
pub struct FeatureRequirement {
    pub feature_name: &'static str,
    // target_arch requirement
    pub feature_req_target_arch: Option<&'static str>,
    // target_family requirement
    pub feature_req_target_family: Option<&'static str>,
}

// We implement a version of default that is const which is not possible through the Default trait
impl FeatureRequirement {
    // As we cannot use cfg!(feature = "feature_name") with something else than a literal, we need
    // a reference to the HashMap we populate with the enabled features
    fn is_activated(&self, build_activated_features: &HashMap<&'static str, bool>) -> bool {
        *build_activated_features.get(self.feature_name).unwrap()
    }

    // panics if the requirements are not met
    fn check_requirements(&self) {
        let target_arch = get_target_arch_cfg();
        if let Some(feature_req_target_arch) = self.feature_req_target_arch {
            if feature_req_target_arch != target_arch {
                panic!(
                    "Feature `{}` requires target_arch `{}`, current cfg: `{}`",
                    self.feature_name, feature_req_target_arch, target_arch
                )
            }
        }

        let target_family = get_target_family_cfg();
        if let Some(feature_req_target_family) = self.feature_req_target_family {
            if feature_req_target_family != target_family {
                panic!(
                    "Feature `{}` requires target_family `{}`, current cfg: `{}`",
                    self.feature_name, feature_req_target_family, target_family
                )
            }
        }
    }
}

// const vecs are not yet a thing so use a fixed size array (update the array size when adding
// requirements)
static FEATURE_REQUIREMENTS: [FeatureRequirement; 4] = [
    FeatureRequirement {
        feature_name: "seeder_x86_64_rdseed",
        feature_req_target_arch: Some("x86_64"),
        feature_req_target_family: None,
    },
    FeatureRequirement {
        feature_name: "generator_x86_64_aesni",
        feature_req_target_arch: Some("x86_64"),
        feature_req_target_family: None,
    },
    FeatureRequirement {
        feature_name: "seeder_unix",
        feature_req_target_arch: None,
        feature_req_target_family: Some("unix"),
    },
    FeatureRequirement {
        feature_name: "generator_aarch64_aes",
        feature_req_target_arch: Some("aarch64"),
        feature_req_target_family: None,
    },
];

// For a "feature_name" feature_cfg!("feature_name") expands to
// ("feature_name", cfg!(feature = "feature_name"))
macro_rules! feature_cfg {
    ($feat_name:literal) => {
        ($feat_name, cfg!(feature = $feat_name))
    };
}

// Static HashMap would require an additional crate (phf or lazy static e.g.), so we just write a
// function that returns the HashMap we are interested in
fn get_feature_enabled_status() -> HashMap<&'static str, bool> {
    HashMap::from([
        feature_cfg!("seeder_x86_64_rdseed"),
        feature_cfg!("generator_x86_64_aesni"),
        feature_cfg!("seeder_unix"),
        feature_cfg!("generator_aarch64_aes"),
    ])
}

// See https://stackoverflow.com/a/43435335/18088947 for the inspiration of this code
fn get_target_arch_cfg() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH is not set")
}

fn get_target_family_cfg() -> String {
    env::var("CARGO_CFG_TARGET_FAMILY").expect("CARGO_CFG_TARGET_FAMILY is not set")
}

fn main() {
    let feature_enabled_status = get_feature_enabled_status();

    // This will panic if some requirements for a feature are not met
    FEATURE_REQUIREMENTS
        .iter()
        .filter(|&req| FeatureRequirement::is_activated(req, &feature_enabled_status))
        .for_each(FeatureRequirement::check_requirements);
}
