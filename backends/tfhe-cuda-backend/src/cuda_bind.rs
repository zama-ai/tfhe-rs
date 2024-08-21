use std::ffi::c_void;

#[link(name = "tfhe_cuda_backend", kind = "static")]
extern "C" {

    pub fn cuda_create_stream(gpu_index: u32) -> *mut c_void;

    pub fn cuda_destroy_stream(stream: *mut c_void, gpu_index: u32);

    pub fn cuda_synchronize_stream(stream: *mut c_void, gpu_index: u32);

    pub fn cuda_malloc(size: u64, gpu_index: u32) -> *mut c_void;

    pub fn cuda_malloc_async(size: u64, stream: *mut c_void, gpu_index: u32) -> *mut c_void;

    pub fn cuda_check_valid_malloc(size: u64, gpu_index: u32);

    pub fn cuda_memcpy_async_to_gpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        stream: *mut c_void,
        gpu_index: u32,
    );

    pub fn cuda_memcpy_async_gpu_to_gpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        stream: *mut c_void,
        gpu_index: u32,
    );

    pub fn cuda_memcpy_async_to_cpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        stream: *mut c_void,
        gpu_index: u32,
    );

    pub fn cuda_memset_async(
        dest: *mut c_void,
        val: u64,
        size: u64,
        stream: *mut c_void,
        gpu_index: u32,
    );

    pub fn cuda_get_number_of_gpus() -> i32;

    pub fn cuda_synchronize_device(gpu_index: u32);

    pub fn cuda_drop(ptr: *mut c_void, gpu_index: u32);

    pub fn cuda_drop_async(ptr: *mut c_void, stream: *mut c_void, gpu_index: u32);

    pub fn cuda_convert_lwe_ciphertext_vector_to_gpu_64(
        stream: *mut c_void,
        gpu_index: u32,
        dest: *mut c_void,
        src: *mut c_void,
        number_of_cts: u32,
        lwe_dimension: u32,
    );

    pub fn cuda_convert_lwe_ciphertext_vector_to_cpu_64(
        stream: *mut c_void,
        gpu_index: u32,
        dest: *mut c_void,
        src: *mut c_void,
        number_of_cts: u32,
        lwe_dimension: u32,
    );

    pub fn cuda_glwe_sample_extract_64(
        stream: *mut c_void,
        gpu_index: u32,
        lwe_array_out: *mut c_void,
        glwe_array_in: *const c_void,
        nth_array: *const u32,
        num_glwes: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
    );

    pub fn scratch_cuda_integer_compress_radix_ciphertext_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        compression_glwe_dimension: u32,
        compression_polynomial_size: u32,
        lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        num_lwes: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        lwe_per_glwe: u32,
        storage_log_modulus: u32,
        allocate_gpu_memory: bool,
    );

    pub fn scratch_cuda_integer_decompress_radix_ciphertext_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        encryption_glwe_dimension: u32,
        encryption_polynomial_size: u32,
        compression_glwe_dimension: u32,
        compression_polynomial_size: u32,
        lwe_dimension: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        num_lwes: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        storage_log_modulus: u32,
        bodies_count: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_compress_radix_ciphertext_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        glwe_array_out: *mut c_void,
        lwe_array_in: *const c_void,
        fp_ksk: *const *mut c_void,
        num_nths: u32,
        mem_ptr: *mut i8,
    );

    pub fn cuda_integer_decompress_radix_ciphertext_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array_out: *mut c_void,
        glwe_in: *const c_void,
        indexes_array: *const c_void,
        indexes_array_size: u32,
        bsks: *const *mut c_void,
        mem_ptr: *mut i8,
    );

    pub fn cleanup_cuda_integer_compress_radix_ciphertext_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn cleanup_cuda_integer_decompress_radix_ciphertext_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn cuda_setup_multi_gpu() -> i32;

    pub fn scratch_cuda_apply_univariate_lut_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        input_lut: *const c_void,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        input_lwe_ciphertext_count: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_apply_univariate_lut_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        output_radix_lwe: *mut c_void,
        input_radix_lwe: *const c_void,
        mem_ptr: *mut i8,
        ksks: *const *mut c_void,
        bsks: *const *mut c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_apply_univariate_lut_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_apply_bivariate_lut_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        input_lut: *const c_void,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        input_lwe_ciphertext_count: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_apply_bivariate_lut_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        output_radix_lwe: *mut c_void,
        input_radix_lwe_1: *const c_void,
        input_radix_lwe_2: *const c_void,
        mem_ptr: *mut i8,
        ksks: *const *mut c_void,
        bsks: *const *mut c_void,
        num_blocks: u32,
        shift: u32,
    );

    pub fn cleanup_cuda_apply_bivariate_lut_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_full_propagation_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_full_propagation_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        input_blocks: *mut c_void,
        mem_ptr: *mut i8,
        ksks: *const *mut c_void,
        bsks: *const *mut c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_full_propagation(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_mult_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        message_modulus: u32,
        carry_modulus: u32,
        glwe_dimension: u32,
        lwe_dimension: u32,
        polynomial_size: u32,
        pbs_base_log: u32,
        pbs_level: u32,
        ks_base_log: u32,
        ks_level: u32,
        grouping_factor: u32,
        num_blocks: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_mult_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        radix_lwe_out: *mut c_void,
        radix_lwe_left: *const c_void,
        radix_lwe_right: *const c_void,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        mem_ptr: *mut i8,
        polynomial_size: u32,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_mult(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn cuda_negate_integer_radix_ciphertext_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        lwe_dimension: u32,
        lwe_ciphertext_count: u32,
        message_modulus: u32,
        carry_modulus: u32,
    );

    pub fn cuda_scalar_addition_integer_radix_ciphertext_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        scalar_input: *const c_void,
        lwe_dimension: u32,
        lwe_ciphertext_count: u32,
        message_modulus: u32,
        carry_modulus: u32,
    );

    pub fn scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        shift_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        shift: u32,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks: u32,
    );

    pub fn scratch_cuda_integer_radix_arithmetic_scalar_shift_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        shift_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_radix_arithmetic_scalar_shift_kb_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        shift: u32,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_radix_logical_scalar_shift(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn cleanup_cuda_integer_radix_arithmetic_scalar_shift(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_shift_and_rotate_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        shift_type: u32,
        is_signed: bool,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_radix_shift_and_rotate_kb_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        lwe_shift: *const c_void,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_radix_shift_and_rotate(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_comparison_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        lwe_ciphertext_count: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        op_type: u32,
        is_signed: bool,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_comparison_integer_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array_out: *mut c_void,
        lwe_array_1: *const c_void,
        lwe_array_2: *const c_void,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        lwe_ciphertext_count: u32,
    );

    pub fn cuda_scalar_comparison_integer_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array_out: *mut c_void,
        lwe_array_in: *const c_void,
        scalar_blocks: *const c_void,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        lwe_ciphertext_count: u32,
        num_scalar_blocks: u32,
    );

    pub fn cleanup_cuda_integer_comparison(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_bitop_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        lwe_ciphertext_count: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        op_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_bitop_integer_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array_out: *mut c_void,
        lwe_array_1: *const c_void,
        lwe_array_2: *const c_void,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        lwe_ciphertext_count: u32,
    );

    pub fn cuda_scalar_bitop_integer_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array_out: *mut c_void,
        lwe_array_input: *const c_void,
        clear_blocks: *const c_void,
        num_clear_blocks: u32,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        lwe_ciphertext_count: u32,
        op: u32,
    );

    pub fn cleanup_cuda_integer_bitop(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_cmux_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        lwe_ciphertext_count: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_cmux_integer_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array_out: *mut c_void,
        lwe_condition: *const c_void,
        lwe_array_true: *const c_void,
        lwe_array_false: *const c_void,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        lwe_ciphertext_count: u32,
    );

    pub fn cleanup_cuda_integer_radix_cmux(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_scalar_rotate_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        shift_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_radix_scalar_rotate_kb_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        n: u32,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_radix_scalar_rotate(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_propagate_single_carry_kb_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_propagate_single_carry_kb_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        carry_out: *mut c_void,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks: u32,
    );

    pub fn cuda_propagate_single_carry_get_input_carries_kb_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        carry_out: *mut c_void,
        input_carries: *mut c_void,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_propagate_single_carry(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_partial_sum_ciphertexts_vec_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks_in_radix: u32,
        max_num_radix_in_vec: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_radix_partial_sum_ciphertexts_vec_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        radix_lwe_out: *mut c_void,
        radix_lwe_vec: *const c_void,
        num_radix_in_vec: u32,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks_in_radix: u32,
    );

    pub fn cleanup_cuda_integer_radix_partial_sum_ciphertexts_vec(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_overflowing_sub_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_radix_overflowing_sub_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        radix_lwe_out: *mut c_void,
        radix_lwe_overflowed: *mut c_void,
        radix_lwe_left: *const c_void,
        radix_lwe_right: *const c_void,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks_in_radix: u32,
    );

    pub fn cleanup_cuda_integer_radix_overflowing_sub(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_scalar_mul_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_scalar_multiplication_integer_radix_ciphertext_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        decomposed_scalar: *const u64,
        has_at_least_one_set: *const u64,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        lwe_dimension: u32,
        polynomial_size: u32,
        message_modulus: u32,
        num_blocks: u32,
        num_scalars: u32,
    );

    pub fn cleanup_cuda_integer_radix_scalar_mul(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_div_rem_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_div_rem_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        quotient: *mut c_void,
        remainder: *mut c_void,
        numerator: *const c_void,
        divisor: *const c_void,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks_in_radix: u32,
    );

    pub fn cleanup_cuda_integer_div_rem(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_signed_overflowing_add_or_sub_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        big_lwe_dimension: u32,
        small_lwe_dimension: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_blocks: u32,
        signed_operation: i8,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_signed_overflowing_add_or_sub_radix_ciphertext_kb_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lhs: *mut c_void,
        rhs: *const c_void,
        overflowed: *mut c_void,
        signed_operation: i8,
        mem_ptr: *mut i8,
        bsks: *const *mut c_void,
        ksks: *const *mut c_void,
        num_blocks_in_radix: u32,
    );

    pub fn cleanup_signed_overflowing_add_or_sub(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_compute_prefix_sum_hillis_steele_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
        input_lut: *const c_void,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        ks_level: u32,
        ks_base_log: u32,
        pbs_level: u32,
        pbs_base_log: u32,
        grouping_factor: u32,
        num_radix_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_compute_prefix_sum_hillis_steele_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        output_radix_lwe: *mut c_void,
        input_radix_lwe: *const c_void,
        mem_ptr: *mut i8,
        ksks: *const *mut c_void,
        bsks: *const *mut c_void,
        num_blocks: u32,
        shift: u32,
    );

    pub fn cleanup_cuda_integer_compute_prefix_sum_hillis_steele_64(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        mem_ptr: *mut *mut i8,
    );

    pub fn cuda_integer_reverse_blocks_64_inplace(
        streams: *const *mut c_void,
        gpu_indexes: *const u32,
        gpu_count: u32,
        lwe_array: *mut c_void,
        num_blocks: u32,
        lwe_size: u32,
    );

    pub fn cuda_keyswitch_lwe_ciphertext_vector_64(
        stream: *mut c_void,
        gpu_index: u32,
        lwe_array_out: *mut c_void,
        lwe_output_indexes: *const c_void,
        lwe_array_in: *const c_void,
        lwe_input_indexes: *const c_void,
        ksk: *const c_void,
        lwe_dimension_in: u32,
        lwe_dimension_out: u32,
        base_log: u32,
        level_count: u32,
        num_samples: u32,
    );

    pub fn scratch_packing_keyswitch_lwe_list_to_glwe_64(
        stream: *mut c_void,
        gpu_index: u32,
        fp_ks_buffer: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        num_lwes: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_packing_keyswitch_lwe_list_to_glwe_64(
        stream: *mut c_void,
        gpu_index: u32,
        glwe_array_out: *mut c_void,
        lwe_array_in: *const c_void,
        fp_ksk_array: *const c_void,
        fp_ks_buffer: *mut i8,
        input_lwe_dimension: u32,
        output_glwe_dimension: u32,
        output_polynomial_size: u32,
        base_log: u32,
        level_count: u32,
        num_lwes: u32,
    );

    pub fn cleanup_packing_keyswitch_lwe_list_to_glwe(
        stream: *mut c_void,
        gpu_index: u32,
        fp_ks_buffer: *mut *mut i8,
    );

    pub fn cuda_negate_lwe_ciphertext_vector_64(
        stream: *mut c_void,
        gpu_index: u32,
        lwe_array_out: *mut c_void,
        lwe_array_in: *const c_void,
        input_lwe_dimension: u32,
        input_lwe_ciphertext_count: u32,
    );

    pub fn cuda_add_lwe_ciphertext_vector_64(
        stream: *mut c_void,
        gpu_index: u32,
        lwe_array_out: *mut c_void,
        lwe_array_in_1: *const c_void,
        lwe_array_in_2: *const c_void,
        input_lwe_dimension: u32,
        input_lwe_ciphertext_count: u32,
    );

    pub fn cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
        stream: *mut c_void,
        gpu_index: u32,
        lwe_array_out: *mut c_void,
        lwe_array_in: *const c_void,
        plaintext_array_in: *const c_void,
        input_lwe_dimension: u32,
        input_lwe_ciphertext_count: u32,
    );

    pub fn cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
        stream: *mut c_void,
        gpu_index: u32,
        lwe_array_out: *mut c_void,
        lwe_array_in: *const c_void,
        cleartext_array_in: *const c_void,
        input_lwe_dimension: u32,
        input_lwe_ciphertext_count: u32,
    );

    pub fn cuda_fourier_polynomial_mul(
        stream: *mut c_void,
        gpu_index: u32,
        input1: *const c_void,
        input2: *const c_void,
        output: *mut c_void,
        polynomial_size: u32,
        total_polynomials: u32,
    );

    pub fn cuda_convert_lwe_programmable_bootstrap_key_64(
        stream: *mut c_void,
        gpu_index: u32,
        dest: *mut c_void,
        src: *const c_void,
        input_lwe_dim: u32,
        glwe_dim: u32,
        level_count: u32,
        polynomial_size: u32,
    );

    pub fn scratch_cuda_programmable_bootstrap_amortized_64(
        stream: *mut c_void,
        gpu_index: u32,
        pbs_buffer: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        input_lwe_ciphertext_count: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_programmable_bootstrap_amortized_lwe_ciphertext_vector_64(
        stream: *mut c_void,
        gpu_index: u32,
        lwe_array_out: *mut c_void,
        lwe_output_indexes: *const c_void,
        lut_vector: *const c_void,
        lut_vector_indexes: *const c_void,
        lwe_array_in: *const c_void,
        lwe_input_indexes: *const c_void,
        bootstrapping_key: *const c_void,
        pbs_buffer: *mut i8,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level_count: u32,
        num_samples: u32,
    );

    pub fn cleanup_cuda_programmable_bootstrap_amortized(
        stream: *mut c_void,
        gpu_index: u32,
        pbs_buffer: *mut *mut i8,
    );

    pub fn scratch_cuda_programmable_bootstrap_64(
        stream: *mut c_void,
        gpu_index: u32,
        pbs_buffer: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        level_count: u32,
        input_lwe_ciphertext_count: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_programmable_bootstrap_lwe_ciphertext_vector_64(
        stream: *mut c_void,
        gpu_index: u32,
        lwe_array_out: *mut c_void,
        lwe_output_indexes: *const c_void,
        lut_vector: *const c_void,
        lut_vector_indexes: *const c_void,
        lwe_array_in: *const c_void,
        lwe_input_indexes: *const c_void,
        bootstrapping_key: *const c_void,
        buffer: *mut i8,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        base_log: u32,
        level_count: u32,
        num_samples: u32,
    );

    pub fn cleanup_cuda_programmable_bootstrap(
        stream: *mut c_void,
        gpu_index: u32,
        pbs_buffer: *mut *mut i8,
    );

    pub fn cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64(
        stream: *mut c_void,
        gpu_index: u32,
        dest: *mut c_void,
        src: *const c_void,
        input_lwe_dim: u32,
        glwe_dim: u32,
        level_count: u32,
        polynomial_size: u32,
        grouping_factor: u32,
    );

    pub fn scratch_cuda_multi_bit_programmable_bootstrap_64(
        stream: *mut c_void,
        gpu_index: u32,
        pbs_buffer: *mut *mut i8,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        level_count: u32,
        grouping_factor: u32,
        input_lwe_ciphertext_count: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
        stream: *mut c_void,
        gpu_index: u32,
        lwe_array_out: *mut c_void,
        lwe_output_indexes: *const c_void,
        lut_vector: *const c_void,
        lut_vector_indexes: *const c_void,
        lwe_array_in: *const c_void,
        lwe_input_indexes: *const c_void,
        bootstrapping_key: *const c_void,
        buffer: *mut i8,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        grouping_factor: u32,
        base_log: u32,
        level_count: u32,
        num_samples: u32,
    );

    pub fn cleanup_cuda_multi_bit_programmable_bootstrap(
        stream: *mut c_void,
        gpu_index: u32,
        pbs_buffer: *mut *mut i8,
    );

} // extern "C"
