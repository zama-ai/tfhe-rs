// concrete-core-ffi/build.rs

#[cfg(feature = "__c_api")]
fn gen_c_api() {
    use std::env;
    use std::path::PathBuf;

    /// Find the location of the `target/` directory. Note that this may be
    /// overridden by `cmake`, so we also need to check the `CARGO_TARGET_DIR`
    /// variable.
    fn target_dir() -> PathBuf {
        if let Ok(target) = env::var("CARGO_TARGET_DIR") {
            PathBuf::from(target)
        } else {
            PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../target/release")
        }
    }

    extern crate cbindgen;
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let output_file = target_dir()
        .join(format!("{}.h", package_name))
        .display()
        .to_string();

    cbindgen::generate(&crate_dir)
        .unwrap()
        .write_to_file(&output_file);
}

fn main() {
    #[cfg(feature = "__c_api")]
    gen_c_api()
}
