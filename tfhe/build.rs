#[cfg(all(feature = "__c_api", not(feature = "__force_skip_cbindgen")))]
fn gen_c_api() {
    use std::env;
    use std::path::PathBuf;

    if std::env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        return;
    }

    fn get_build_profile_name() -> String {
        // The profile name is always the 3rd last part of the path (with 1 based indexing).
        // e.g. /code/core/target/cli/build/my-build-info-9f91ba6f99d7a061/out
        let out_dir = std::env::var("OUT_DIR")
            .expect("OUT_DIR is not set, cannot determine build profile, aborting");
        out_dir
            .split(std::path::MAIN_SEPARATOR)
            .nth_back(3)
            .expect("Cannot determine build profile, aborting")
            .to_string()
    }

    /// Find the location of the `target/` directory. Note that this may be
    /// overridden by `cmake`, so we also need to check the `CARGO_TARGET_DIR`
    /// variable.
    fn target_dir() -> PathBuf {
        if let Ok(target) = env::var("CARGO_TARGET_DIR") {
            PathBuf::from(target)
        } else {
            PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
                .join(format!("../target/{}", get_build_profile_name()))
        }
    }

    extern crate cbindgen;
    let crate_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let output_file = target_dir().join(format!("{package_name}.h"));

    let parse_expand_features_vec = vec![
        // Note that this list may not be complete, but as macro expansion is used mostly/only for
        // the C API and the HL API, this is fine, if the C API build fails or generates invalid
        // headers then you likely need to add other features that will be forwarded to Cargo
        // expand
        #[cfg(feature = "__c_api")]
        "__c_api",
        #[cfg(feature = "boolean-c-api")]
        "boolean-c-api",
        #[cfg(feature = "shortint-c-api")]
        "shortint-c-api",
        #[cfg(feature = "high-level-c-api")]
        "high-level-c-api",
        #[cfg(feature = "boolean")]
        "boolean",
        #[cfg(feature = "shortint")]
        "shortint",
        #[cfg(feature = "integer")]
        "integer",
        #[cfg(feature = "gpu")]
        "gpu",
        #[cfg(feature = "zk-pok")]
        "zk-pok",
    ];

    let parse_expand_vec = if parse_expand_features_vec.is_empty() {
        vec![]
    } else {
        vec![package_name.as_str()]
    };

    cbindgen::Builder::new()
        .with_crate(crate_dir.as_path())
        .with_config(cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")).unwrap())
        .with_parse_expand(&parse_expand_vec)
        .with_parse_expand_features(&parse_expand_features_vec)
        .generate()
        .unwrap()
        .write_to_file(output_file);
}

fn main() {
    #[cfg(all(feature = "__c_api", not(feature = "__force_skip_cbindgen")))]
    gen_c_api()
}
