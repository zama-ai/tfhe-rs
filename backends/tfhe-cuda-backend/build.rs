use std::path::PathBuf;
use std::process::Command;

fn main() {
    if let Ok(val) = std::env::var("DOCS_RS") {
        if val.parse::<u32>() == Ok(1) {
            return;
        }
    }

    // This is a workaround to the current nightly toolchain (2024-06-27 which started with
    // toolchain 2024-05-05) build issue
    // Essentially if cbindgen is running, a wrong argument ends up forwarded to the cuda backend
    // "make" command during macro expansions for TFHE-rs C API, crashing make for make < 4.4 and
    // thus crashing the build
    // On the other hand, this speeds up C API build greatly given we don't have macro expansions
    // in the CUDA backend so this skips the second compilation of TFHE-rs for macro inspection by
    // cbindgen
    if std::env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        return;
    }

    println!("Build tfhe-cuda-backend");
    println!("cargo::rerun-if-changed=cuda/include");
    println!("cargo::rerun-if-changed=cuda/src");
    println!("cargo::rerun-if-changed=cuda/tests_and_benchmarks");
    println!("cargo::rerun-if-changed=cuda/CMakeLists.txt");
    println!("cargo::rerun-if-changed=src");

    if std::env::consts::OS == "linux" {
        let output = Command::new("./get_os_name.sh").output().unwrap();
        let distribution = String::from_utf8(output.stdout).unwrap();
        if distribution != "Ubuntu\n" {
            println!(
                "cargo:warning=This Linux distribution is not officially supported. \
                Only Ubuntu is supported by tfhe-cuda-backend at this time. Build may fail\n"
            );
        }

        let dest = cmake::build("cuda");
        println!("cargo:rustc-link-search=native={}", dest.display());
        println!("cargo:rustc-link-lib=static=tfhe_cuda_backend");

        // Try to find the cuda libs with pkg-config, default to the path used by the nvidia runfile
        if pkg_config::Config::new()
            .atleast_version("10")
            .probe("cuda")
            .is_err()
        {
            println!("cargo:rustc-link-search=native=/usr/local/cuda/lib64");
        }
        println!("cargo:rustc-link-lib=gomp");
        println!("cargo:rustc-link-lib=cudart");
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu/");
        println!("cargo:rustc-link-lib=stdc++");

        let header_path = "wrapper.h";
        let headers = vec![
            "wrapper.h",
            "cuda/include/ciphertext.h",
            "cuda/include/integer/compression/compression.h",
            "cuda/include/integer/integer.h",
            "cuda/include/keyswitch.h",
            "cuda/include/linear_algebra.h",
            "cuda/include/pbs/programmable_bootstrap.h",
            "cuda/include/pbs/programmable_bootstrap_multibit.h",
        ];
        let out_path = PathBuf::from("src").join("bindings.rs");
        let bindings_modified = if out_path.exists() {
            std::fs::metadata(&out_path).unwrap().modified().unwrap()
        } else {
            std::time::SystemTime::UNIX_EPOCH // If bindings file doesn't exist, consider it older
        };
        let mut headers_modified = bindings_modified;
        for header in headers {
            println!("cargo:rerun-if-changed={}", header);
            // Check modification times
            let header_modified = std::fs::metadata(header).unwrap().modified().unwrap();
            if header_modified > headers_modified {
                headers_modified = header_modified;
            }
        }

        // Regenerate bindings only if header has been modified
        if headers_modified > bindings_modified {
            let bindings = bindgen::Builder::default()
                .header(header_path)
                // allow only what we are interested in, the custom types appearing in the interface
                .allowlist_type("PBS_TYPE")
                .allowlist_type("SHIFT_OR_ROTATE_TYPE")
                // and the functions reachable from the headers included in wrapper.h
                .allowlist_function(".*")
                .clang_arg("-x")
                .clang_arg("c++")
                .clang_arg("-std=c++17")
                .clang_arg("-I/usr/include")
                .clang_arg("-I/usr/local/include")
                .ctypes_prefix("ffi")
                .raw_line("use crate::ffi;")
                .generate()
                .expect("Unable to generate bindings");

            bindings
                .write_to_file(&out_path)
                .expect("Couldn't write bindings!");
        }
    } else {
        panic!(
            "Error: platform not supported, tfhe-cuda-backend not built (only Linux is supported)"
        );
    }
}
