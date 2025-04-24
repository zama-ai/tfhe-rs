fn main() {
    if cfg!(feature = "hw-xrt") {
        println!("cargo:rustc-link-search=/opt/xilinx/xrt/lib");
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=rt");
        println!("cargo:rustc-link-lib=uuid");
        println!("cargo:rustc-link-lib=dylib=xrt_coreutil");

        cxx_build::bridge("src/ffi/xrt/mod.rs")
            .file("src/ffi/xrt/cxx/hpu_hw.cc")
            .file("src/ffi/xrt/cxx/mem_zone.cc")
            .flag_if_supported("-std=c++23")
            .include("/opt/xilinx/xrt/include") // Enhance: support parsing bash env instead of hard path
            .flag("-fmessage-length=0")
            .compile("hpu-hw-ffi");

        println!("cargo:rerun-if-changed=src/ffi/xrt/mod.rs");
        println!("cargo:rerun-if-changed=src/ffi/xrt/cxx/hpu_hw.cc");
        println!("cargo:rerun-if-changed=src/ffi/xrt/cxx/hpu_hw.h");
        println!("cargo:rerun-if-changed=src/ffi/xrt/cxx/mem_zone.cc");
        println!("cargo:rerun-if-changed=src/ffi/xrt/cxx/mem_zone.h");
    } else {
        // Simulation ffi -> nothing to do
    }
}
