use std::path::PathBuf;

fn get_linux_distribution_name() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("NAME=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

fn generate_bindings() {
    let header_path = "wrapper.h";
    let headers = vec![header_path, "cuda/include/device.h"];
    let out_path = PathBuf::from("src").join("cuda_bind.rs");

    let bindings_modified = if out_path.exists() {
        std::fs::metadata(&out_path).unwrap().modified().unwrap()
    } else {
        std::time::SystemTime::UNIX_EPOCH
    };

    let mut headers_modified = bindings_modified;
    for header in &headers {
        println!("cargo:rerun-if-changed={header}");
        let header_modified = std::fs::metadata(header).unwrap().modified().unwrap();
        if header_modified > headers_modified {
            headers_modified = header_modified;
        }
    }

    if headers_modified > bindings_modified {
        // Map cudaStream_t / cudaEvent_t to *mut c_void so callers don't need
        // casts when storing them alongside other void pointers.
        let bindings = bindgen::Builder::default()
            .header(header_path)
            .allowlist_function("^cuda_.*")
            .blocklist_type("CUstream_st")
            .blocklist_type("cudaStream_t")
            .blocklist_type("CUevent_st")
            .blocklist_type("cudaEvent_t")
            .raw_line("pub type cudaStream_t = *mut ::std::os::raw::c_void;")
            .raw_line("pub type cudaEvent_t = *mut ::std::os::raw::c_void;")
            .clang_arg("-x")
            .clang_arg("c++")
            .clang_arg("-std=c++17")
            .clang_arg("-I/usr/local/cuda/include")
            .ctypes_prefix("::std::os::raw")
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file(&out_path)
            .expect("Couldn't write bindings!");
    }
}

fn main() {
    if let Ok(val) = std::env::var("DOCS_RS") {
        if val.parse::<u32>() == Ok(1) {
            return;
        }
    }

    if std::env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        return;
    }

    println!("cargo::rerun-if-changed=cuda/include");
    println!("cargo::rerun-if-changed=cuda/src");
    println!("cargo::rerun-if-changed=cuda/CMakeLists.txt");
    println!("cargo::rerun-if-changed=src");

    if std::env::consts::OS == "linux" {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR must be set by cargo during build");

        if get_linux_distribution_name().as_deref() != Some("Ubuntu") {
            println!(
                "cargo:warning=This Linux distribution is not officially supported. \
                Only Ubuntu is supported by tfhe-cuda-common at this time. Build may fail\n"
            );
        }

        let mut cmake_config = cmake::Config::new("cuda");

        if cfg!(feature = "profile") {
            cmake_config.define("USE_NVTOOLS", "ON");
        } else {
            cmake_config.define("USE_NVTOOLS", "OFF");
        }

        if cfg!(feature = "debug") {
            cmake_config.define("CMAKE_BUILD_TYPE", "Debug");
        }

        let dest = cmake_config.build();

        println!(
            "cargo:rustc-link-search=native={}",
            dest.join("lib").display()
        );
        println!("cargo:rustc-link-lib=static=tfhe_cuda_common");

        if pkg_config::Config::new()
            .atleast_version("10")
            .probe("cuda")
            .is_err()
        {
            println!("cargo:rustc-link-search=native=/usr/local/cuda/lib64");
        }

        println!("cargo:rustc-link-lib=cudart");
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu/");
        println!("cargo:rustc-link-lib=stdc++");

        generate_bindings();

        // When a build script emits `cargo:KEY=VALUE` and the crate declares
        // `links = "foo"` in Cargo.toml, Cargo exposes it to dependent crates
        // as the env var DEP_FOO_KEY.
        //
        // "include" is not a built-in Cargo directive, just a convention. In this case:
        //   - links = "tfhe_cuda_common" + cargo:include=<path>
        //   - dependents see DEP_TFHE_CUDA_COMMON_INCLUDE=<path>
        let include_dir = std::path::PathBuf::from(&manifest_dir).join("cuda/include");
        println!("cargo:include={}", include_dir.display());

        // Same mechanism: dependents see DEP_TFHE_CUDA_COMMON_CHECK_CUDA_DIR.
        let cuda_dir = std::path::PathBuf::from(&manifest_dir).join("cuda");
        println!("cargo:check_cuda_dir={}", cuda_dir.display());
    } else {
        panic!(
            "Error: platform not supported, tfhe-cuda-common not built (only Linux is supported)"
        );
    }
}
