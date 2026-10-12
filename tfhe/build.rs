#[cfg(all(feature = "__c_api", not(feature = "__force_skip_cbindgen")))]
fn gen_c_api() {
    use std::env;
    use std::path::PathBuf;

    if std::env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        return;
    }

    fn header_output_dir() -> PathBuf {
        let out_dir = std::env::var("OUT_DIR")
            .expect("OUT_DIR is not set, cannot locate where to output tfhe.h");
        let mut out_dir_path = PathBuf::from(&out_dir);
        let pkg_name = std::env::var("CARGO_PKG_NAME").expect("Cannot get our own name");

        // OUT_DIR format
        // Old : OUT_DIR = <build-dir>/[<triple>/]<profile>/build/<pkg>-<hash>/out
        // New : OUT_DIR = <build-dir>/[<triple>/]<profile>/build/<pkg>/<hash>/out
        // Notice the additional dir for pkg in new, containing the hash dirs

        // check the last component of the path
        while let Some(last_component_name) = out_dir_path.file_name() {
            let last_component_name = last_component_name.to_str().expect(
                "Should not fail, OUT_DIR is a String, all components should be valid UTF-8",
            );
            // If this component starts with our pkg_name e.g. "tfhe"
            // Then this is the fragment after "build", meaning two parents up is the profile dir
            if last_component_name.starts_with(&pkg_name) {
                return out_dir_path
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .to_path_buf();
            } else {
                out_dir_path = out_dir_path.parent().unwrap().to_path_buf();
                continue;
            }
        }

        panic!("could not find the profile dir in the out_dir path: {out_dir}");
    }

    extern crate cbindgen;
    let crate_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let output_file = header_output_dir().join(format!("{package_name}.h"));

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
        #[cfg(feature = "extended-types")]
        "extended-types",
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
