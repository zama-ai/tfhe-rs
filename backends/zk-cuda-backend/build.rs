use std::path::PathBuf;

fn main() {
    if let Ok(val) = std::env::var("DOCS_RS") {
        if val.parse::<u32>() == Ok(1) {
            return;
        }
    }

    if std::env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        return;
    }

    println!("Build zk-cuda-backend");
    println!("cargo::rerun-if-changed=cuda/include");
    println!("cargo::rerun-if-changed=cuda/src");
    println!("cargo::rerun-if-changed=cuda/CMakeLists.txt");
    println!("cargo::rerun-if-changed=src");

    // Platform/distro check is performed by tfhe-cuda-common's build.rs, which
    // Cargo builds first as a dependency.
    if std::env::consts::OS == "linux" {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR must be set by cargo during build");

        let mut cmake_config = cmake::Config::new("cuda");

        if let Ok(common_include) = std::env::var("DEP_TFHE_CUDA_COMMON_INCLUDE") {
            cmake_config.define("TFHE_CUDA_COMMON_INCLUDE_DIR", &common_include);
        }

        let dest = cmake_config.build();

        // cmake crate installs to dest/lib subdirectory
        println!(
            "cargo:rustc-link-search=native={}",
            dest.join("lib").display()
        );
        println!("cargo:rustc-link-lib=static=zk_cuda_backend");

        // Find CUDA libs with pkg_config, fallback to standard path if not found
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

        // Generate Rust bindings from C headers using bindgen
        let header_path = PathBuf::from(&manifest_dir).join("wrapper.h");
        let headers = vec![
            "wrapper.h",
            "src/include/api.h",
            "cuda/include/curve.h",
            "cuda/include/fp.h",
            "cuda/include/fp2.h",
        ];
        let out_path = PathBuf::from(&manifest_dir).join("src").join("bindings.rs");

        // Check if bindings need regeneration by comparing modification times
        let bindings_modified = if out_path.exists() {
            std::fs::metadata(&out_path).unwrap().modified().unwrap()
        } else {
            std::time::SystemTime::UNIX_EPOCH
        };

        let mut headers_modified = bindings_modified;
        for header in &headers {
            println!("cargo:rerun-if-changed={header}");
            let header_path = PathBuf::from(&manifest_dir).join(header);
            let header_modified = std::fs::metadata(&header_path).unwrap().modified().unwrap();
            if header_modified > headers_modified {
                headers_modified = header_modified;
            }
        }

        // Regenerate bindings only if headers have changed
        if headers_modified > bindings_modified {
            // Use absolute paths for include directories
            let cuda_include = PathBuf::from(&manifest_dir).join("cuda/include");
            let src_include = PathBuf::from(&manifest_dir).join("src/include");

            let bindings = bindgen::Builder::default()
                .header(header_path.to_str().unwrap())
                // Allow only the wrapper functions (C FFI interface)
                .allowlist_function(".*_wrapper(_async)?")
                // Allow the core types needed for FFI
                .allowlist_type("G1Point")
                .allowlist_type("G2Point")
                .allowlist_type("G1ProjectivePoint")
                .allowlist_type("G2ProjectivePoint")
                .allowlist_type("Fp")
                .allowlist_type("Fp2")
                .allowlist_type("Scalar")
                .allowlist_type("BigInt")
                .allowlist_type("cudaStream_t")
                // Derive Default, PartialEq and Eq for all types so wrapper
                // types can use derive macros instead of manual impls
                .derive_default(true)
                .derive_partialeq(true)
                .derive_eq(true)
                .clang_arg("-x")
                .clang_arg("c++")
                .clang_arg("-std=c++17")
                // Include paths for the header files (absolute paths)
                .clang_arg(format!("-I{}", manifest_dir))
                .clang_arg(format!("-I{}", cuda_include.display()))
                .clang_arg(format!("-I{}", src_include.display()))
                .clang_arg("-I/usr/include")
                .clang_arg("-I/usr/local/include")
                .clang_arg("-I/usr/local/cuda/include")
                .generate()
                .expect("Unable to generate bindings");

            bindings
                .write_to_file(&out_path)
                .expect("Couldn't write bindings!");
        }
    } else {
        panic!(
            "Error: platform not supported, zk-cuda-backend not built (only Linux is supported)"
        );
    }
}
