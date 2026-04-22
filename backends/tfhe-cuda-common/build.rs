fn get_linux_distribution_name() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("NAME=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
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

        // Expose the include path so dependent crates can access headers via
        // DEP_TFHE_CUDA_COMMON_INCLUDE
        let include_dir = std::path::PathBuf::from(&manifest_dir).join("cuda/include");
        println!("cargo:include={}", include_dir.display());
    } else {
        panic!(
            "Error: platform not supported, tfhe-cuda-common not built (only Linux is supported)"
        );
    }
}
