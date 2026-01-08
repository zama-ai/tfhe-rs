use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only add GNU-specific linker flags on Linux
    // These are needed to handle duplicate symbols between tfhe-cuda-backend and zk-cuda-backend
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-arg=-Wl,--allow-multiple-definition");
        println!("cargo:rustc-link-arg=-Wl,--no-as-needed");
    }

    // When building documentation (DOCS_RS=1), skip CUDA compilation
    // This allows docs to be built on machines without CUDA installed
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=DOCS_RS is set, skipping CUDA build for documentation");
        return;
    }

    // Always use fp_arithmetic (without device.cu).
    // Device utilities are provided by tfhe-cuda-backend.
    const LIB_NAME: &str = "fp_arithmetic";

    // Tell cargo to link against the C++ library
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // The CMake project is in the cuda/ subdirectory
    let cuda_dir = manifest_dir.join("cuda");
    let build_dir = cuda_dir.join("build");

    // Check if the library exists
    let lib_file = build_dir.join(format!("lib{}.a", LIB_NAME));
    let lib_exists = lib_file.exists();
    let lib_time = std::fs::metadata(&lib_file)
        .ok()
        .and_then(|m| m.modified().ok());

    // Always rebuild if library doesn't exist
    let mut needs_rebuild = !lib_exists;

    // Check c_wrapper.cu for changes
    if !needs_rebuild {
        let c_wrapper = manifest_dir.join("src").join("c_wrapper.cu");
        if c_wrapper.exists() {
            if let Ok(cw_meta) = std::fs::metadata(&c_wrapper) {
                if let Ok(cw_time) = cw_meta.modified() {
                    if lib_time.map(|lt| cw_time > lt).unwrap_or(true) {
                        needs_rebuild = true;
                    }
                }
            }
        }
    }

    // Check all C++ source files in zk-cuda-backend/cuda/src/
    if !needs_rebuild {
        let src_dir = cuda_dir.join("src");
        if src_dir.exists() {
            // Check files in src/ and src/primitives/
            const CU_FILES: &[&str] = &[
                "curve.cu",
                "primitives/fp.cu",
                "primitives/fp2.cu",
                "msm/msm.cu",
                "msm/naive/msm_naive.cu",
                "msm/pippenger/msm_pippenger.cu",
            ];
            for file in CU_FILES {
                let file_path = src_dir.join(file);
                if file_path.exists() {
                    if let Ok(file_meta) = std::fs::metadata(&file_path) {
                        if let Ok(file_time) = file_meta.modified() {
                            if lib_time.map(|lt| file_time > lt).unwrap_or(true) {
                                needs_rebuild = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // If library doesn't exist or any C++ source file is newer, trigger CMake rebuild
    if needs_rebuild {
        if !lib_exists {
            println!(
                "cargo:warning=lib{}.a does not exist, building CMake project...",
                LIB_NAME
            );
        } else {
            println!(
                "cargo:warning=C++ source files are newer than lib{}.a, rebuilding CMake project...",
                LIB_NAME
            );
        }

        // Ensure build directory exists
        std::fs::create_dir_all(&build_dir).expect("Failed to create build directory");

        // First ensure CMake is configured
        // Note: tests/benchmarks are off by default, so they won't be built
        if !build_dir.join("CMakeCache.txt").exists() {
            println!("cargo:warning=CMake not configured, running cmake...");
            let configure_status = Command::new("cmake")
                .arg("-B")
                .arg(&build_dir)
                .arg("-S")
                .arg(&cuda_dir)
                .arg("-DCMAKE_BUILD_TYPE=Release")
                .status()
                .expect("Failed to run cmake configure");

            if !configure_status.success() {
                panic!("CMake configuration failed! Make sure CUDA toolkit is installed.");
            }
        }

        // Build the library
        let mut build_cmd = Command::new("cmake");
        build_cmd
            .arg("--build")
            .arg(&build_dir)
            .arg("--target")
            .arg(LIB_NAME);

        // For multi-config generators (Windows), use --config
        // For single-config generators (Unix), CMAKE_BUILD_TYPE is set during configure
        #[cfg(windows)]
        {
            build_cmd.arg("--config").arg("Release");
        }

        let status = build_cmd.status().expect("Failed to run cmake --build");

        if !status.success() {
            panic!("CMake build failed for target {}!", LIB_NAME);
        }

        println!("cargo:warning=CMake build completed successfully");

        // Verify the library was created
        if !lib_file.exists() {
            panic!(
                "CMake build completed but lib{}.a was not created at {}",
                LIB_NAME,
                lib_file.display()
            );
        }
    }

    // Add CUDA library paths first (before linking our library)
    if let Ok(cuda_path) = env::var("CUDA_PATH") {
        println!("cargo:rustc-link-search=native={}/lib64", cuda_path);
    } else if let Ok(cuda_home) = env::var("CUDA_HOME") {
        println!("cargo:rustc-link-search=native={}/lib64", cuda_home);
    } else {
        // Try common CUDA installation paths
        const COMMON_PATHS: &[&str] = &[
            "/usr/local/cuda/lib64",
            "/usr/lib/x86_64-linux-gnu",
            "/opt/cuda/lib64",
        ];
        for path in COMMON_PATHS {
            if PathBuf::from(path).exists() {
                println!("cargo:rustc-link-search=native={}", path);
            }
        }
    }

    // Library is in build/ directory, not build/lib/
    println!("cargo:rustc-link-search=native={}", build_dir.display());

    // Link fp_arithmetic without whole-archive since device code registration
    // symbols come from tfhe-cuda-backend
    println!("cargo:rustc-link-lib=static={}", LIB_NAME);

    // Link CUDA runtime (after our library) to provide CUDA runtime functions
    println!("cargo:rustc-link-lib=dylib=cudart");

    // Link against C++ standard library (required for CUDA code)
    println!("cargo:rustc-link-lib=stdc++");

    // Rebuild if the C++ library changes
    println!(
        "cargo:rerun-if-changed={}",
        build_dir.join(format!("lib{}.a", LIB_NAME)).display()
    );

    // Rebuild if C wrapper changes
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("src").join("c_wrapper.cu").display()
    );

    // Rebuild if any C++ source files in zk-cuda-backend/cuda/src/ change
    let src_dir = cuda_dir.join("src");
    if src_dir.exists() {
        // Watch the entire src directory for changes
        println!("cargo:rerun-if-changed={}", src_dir.display());

        // Also explicitly watch individual .cu files for better granularity
        const CU_FILES: &[&str] = &[
            "curve.cu",
            "primitives/fp.cu",
            "primitives/fp2.cu",
            "msm/msm.cu",
            "msm/naive/msm_naive.cu",
            "msm/pippenger/msm_pippenger.cu",
        ];
        for file in CU_FILES {
            let file_path = src_dir.join(file);
            if file_path.exists() {
                println!("cargo:rerun-if-changed={}", file_path.display());
            }
        }
    }

    // Rebuild if any header files in zk-cuda-backend/cuda/include/ change
    let include_dir = cuda_dir.join("include");
    if include_dir.exists() {
        println!("cargo:rerun-if-changed={}", include_dir.display());
    }
}
