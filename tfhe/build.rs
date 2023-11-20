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

fn panic_if_non_optimized_build() {
    // This has a lot of \n and \ to control formatting precisely
    const ERROR_MESSAGE: &str = "\
    It seems that tfhe-rs is being compiled with insufficient optimization level.\n\
    FHE is already slow on its own, and so compiler optimizations have to be turned on.\n\
    \n\
    By default rust/cargo does not enable optimizations, make sure you build/run with the \n\
    release flag:\n    \
    - `cargo run --release`\n    \
    - `cargo build --release`\n\
    (Note that doing `cargo build --release && cargo run`, will build in release mode\n\
     but then rebuild in debug mode and run in debug mode)\n
    \n\
    * If you wish to be able to use a debugger, consider adding the following lines \n\
    to the projects's Cargo.toml and compile in release\n\
    \t```\n\
    \t[profile.release]\n\
    \tdebug = true\n\
    \t```\n\
    \t\n\
    * It is also possible to override the opt-level only for tfhe-rs in the Cargo.toml\n\
    \t```\n\
    \t[profile.dev.package.tfhe]\n\
    \topt-level=3\n\
    \t```\n\
    \tMore generally:\n\
    \t```\n\
    \t[profile.profile_name.package.tfhe]\n\
    \topt-level=3\n\
    \t```\n\
    \t\n\
    * If you really need a non optimized / less optimized build set the environment variable:\n\
    \t```\n\
    \texport TFHE_RS_ALLOW_NON_OPTIMIZED_BUILD=true\n\
    \t```\n\
    Or in .cargo/config.toml add\n\
    \t```\n\
    \t[env]\n\
    \tTFHE_RS_ALLOW_NON_OPTIMIZED_BUILD=\"true\"\n\
    ```\n\
";
    if option_env!("CARGO_PRIMARY_PACKAGE").is_none() {
        // If CARGO_PRIMARY_PACKAGE is set, then we are build tfhe-rs is not being built
        // as a dependency.
        match std::env::var("TFHE_RS_ALLOW_NON_OPTIMIZED_BUILD") {
            Ok(value) if value == "true" => {}
            // Either the variable is defined but with not the correct value
            // Or undefined, or other some kind of errors we consider those cases equal anyway
            _ => {
                let opt_level_string = std::env::var("OPT_LEVEL").expect(
                    "Unable to get opt-level from cargo ('OPT_LEVEL' enviromnent variable not set)",
                );
                let opt_level = opt_level_string
                    .parse::<i32>()
                    .expect("Failed to parse opt-level");
                if opt_level < 3 {
                    panic!("{ERROR_MESSAGE}");
                }
            }
        }
    }
}

fn main() {
    panic_if_non_optimized_build();
    #[cfg(all(feature = "__c_api", not(feature = "__force_skip_cbindgen")))]
    gen_c_api()
}
