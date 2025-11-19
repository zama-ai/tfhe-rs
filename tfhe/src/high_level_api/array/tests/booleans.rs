#[test]
fn test_cpu_only_bitand() {
    let ck = super::setup_default_cpu();
    super::bitand_test_case::<
        crate::FheBoolId,
        crate::high_level_api::array::cpu::CpuFheBoolArrayBackend,
        bool,
    >(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitand() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let ck = setup_fn();
        super::bitand_test_case::<
            crate::FheBoolId,
            crate::high_level_api::array::gpu::GpuFheBoolArrayBackend,
            bool,
        >(&ck);
    }
}

#[test]
fn test_cpu_dyn_bitand() {
    let ck = super::setup_default_cpu();
    super::bitand_test_case::<
        crate::FheBoolId,
        crate::high_level_api::array::dynamic::DynFheBoolArrayBackend,
        bool,
    >(&ck);
}

#[test]
fn test_cpu_only_bitor() {
    let ck = super::setup_default_cpu();
    super::bitor_test_case::<crate::CpuFheBoolArray, bool>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitor() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let ck = setup_fn();
        super::bitor_test_case::<crate::high_level_api::array::gpu::GpuFheBoolArray, bool>(&ck);
    }
}

#[test]
fn test_cpu_dyn_bitor() {
    let ck = super::setup_default_cpu();
    super::bitor_test_case::<crate::FheBoolArray, bool>(&ck);
}

#[test]
fn test_cpu_only_bitxor() {
    let ck = super::setup_default_cpu();
    super::bitxor_test_case::<crate::CpuFheBoolArray, bool>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitxor() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let ck = setup_fn();
        super::bitxor_test_case::<crate::high_level_api::array::gpu::GpuFheBoolArray, bool>(&ck);
    }
}

#[test]
fn test_cpu_dyn_bitxor() {
    let ck = super::setup_default_cpu();
    super::bitxor_test_case::<crate::FheBoolArray, bool>(&ck);
}

#[test]
fn test_cpu_only_bitand_scalar_slice() {
    let ck = super::setup_default_cpu();
    super::bitand_scalar_slice_test_case::<crate::CpuFheBoolArray, bool>(&ck);
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_only_bitand_scalar_slice() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let ck = setup_fn();
        super::bitand_scalar_slice_test_case::<
            crate::high_level_api::array::gpu::GpuFheBoolArray,
            bool,
        >(&ck);
    }
}

#[test]
fn test_cpu_dyn_bitand_scalar_slice() {
    let ck = super::setup_default_cpu();
    super::bitand_scalar_slice_test_case::<crate::FheBoolArray, bool>(&ck);
}
