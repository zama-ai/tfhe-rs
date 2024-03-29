use std::ffi::c_void;

#[link(name = "tfhe_cuda_backend", kind = "static")]
extern "C" {

    /// Create a new Cuda stream on GPU `gpu_index`
    pub fn cuda_create_stream(gpu_index: u32) -> *mut c_void;

    /// Destroy the Cuda stream `v_stream`
    pub fn cuda_destroy_stream(v_stream: *mut c_void);

    /// Allocate `size` memory on GPU `gpu_index` asynchronously
    pub fn cuda_malloc_async(size: u64, v_stream: *const c_void) -> *mut c_void;

    /// Copy `size` memory asynchronously from `src` on GPU `gpu_index` to `dest` on CPU using
    /// the Cuda stream `v_stream`.
    pub fn cuda_memcpy_async_to_cpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        v_stream: *const c_void,
    );

    /// Copy `size` memory asynchronously from `src` on CPU to `dest` on GPU `gpu_index` using
    /// the Cuda stream `v_stream`.
    pub fn cuda_memcpy_async_to_gpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        v_stream: *const c_void,
    );

    /// Copy `size` memory asynchronously from `src` to `dest` on the same GPU `gpu_index` using
    /// the Cuda stream `v_stream`.
    pub fn cuda_memcpy_async_gpu_to_gpu(
        dest: *mut c_void,
        src: *const c_void,
        size: u64,
        v_stream: *const c_void,
    );

    /// Copy `size` memory asynchronously from `src` on CPU to `dest` on GPU `gpu_index` using
    /// the Cuda stream `v_stream`.
    pub fn cuda_memset_async(dest: *mut c_void, value: u64, size: u64, v_stream: *const c_void);

    /// Get the total number of Nvidia GPUs detected on the platform
    pub fn cuda_get_number_of_gpus() -> i32;

    /// Synchronize all streams on GPU `gpu_index`
    pub fn cuda_synchronize_device(gpu_index: u32);

    /// Synchronize Cuda stream
    pub fn cuda_synchronize_stream(v_stream: *const c_void);

    /// Free memory for pointer `ptr` on GPU `gpu_index` asynchronously, using stream `v_stream`
    pub fn cuda_drop_async(ptr: *mut c_void, v_stream: *const c_void);

    /// Free memory for pointer `ptr` on GPU `gpu_index` synchronously
    pub fn cuda_drop(ptr: *mut c_void, gpu_index: u32);

    /// Get the maximum amount of shared memory on GPU `gpu_index`
    pub fn cuda_get_max_shared_memory(gpu_index: u32) -> i32;

    /// Copy a bootstrap key `src` represented with 64 bits in the standard domain from the CPU to
    /// the GPU `gpu_index` using the stream `v_stream`, and convert it to the Fourier domain on the
    /// GPU. The resulting bootstrap key `dest` on the GPU is an array of f64 values.
    pub fn cuda_convert_lwe_programmable_bootstrap_key_64(
        dest: *mut c_void,
        src: *const c_void,
        v_stream: *const c_void,
        input_lwe_dim: u32,
        glwe_dim: u32,
        level_count: u32,
        polynomial_size: u32,
    );

    /// Copy a multi-bit bootstrap key `src` represented with 64 bits in the standard domain from
    /// the CPU to the GPU `gpu_index` using the stream `v_stream`. The resulting bootstrap key
    /// `dest` on the GPU is an array of uint64_t values.
    pub fn cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64(
        dest: *mut c_void,
        src: *const c_void,
        v_stream: *const c_void,
        input_lwe_dim: u32,
        glwe_dim: u32,
        level_count: u32,
        polynomial_size: u32,
        grouping_factor: u32,
    );

    /// Copy `number_of_cts` LWE ciphertext represented with 64 bits in the standard domain from the
    /// CPU to the GPU `gpu_index` using the stream `v_stream`. All ciphertexts must be
    /// concatenated.
    pub fn cuda_convert_lwe_ciphertext_vector_to_gpu_64(
        dest: *mut c_void,
        src: *mut c_void,
        v_stream: *const c_void,
        number_of_cts: u32,
        lwe_dimension: u32,
    );

    /// Copy `number_of_cts` LWE ciphertext represented with 64 bits in the standard domain from the
    /// GPU to the CPU `gpu_index` using the stream `v_stream`. All ciphertexts must be
    /// concatenated.
    pub fn cuda_convert_lwe_ciphertext_vector_to_cpu_64(
        dest: *mut c_void,
        src: *mut c_void,
        v_stream: *const c_void,
        number_of_cts: u32,
        lwe_dimension: u32,
    );

    /// This scratch function allocates the necessary amount of data on the GPU for
    /// the low latency PBS on 64-bit inputs, into `pbs_buffer`. It also configures SM
    /// options on the GPU in case FULLSM or PARTIALSM mode are going to be used.
    pub fn scratch_cuda_programmable_bootstrap_64(
        v_stream: *const c_void,
        pbs_buffer: *mut *mut i8,
        glwe_dimension: u32,
        polynomial_size: u32,
        level_count: u32,
        input_lwe_ciphertext_count: u32,
        max_shared_memory: u32,
        allocate_gpu_memory: bool,
    );

    /// Perform bootstrapping on a batch of input u64 LWE ciphertexts.
    ///
    /// - `v_stream` is a void pointer to the Cuda stream to be used in the kernel launch
    /// - `gpu_index` is the index of the GPU to be used in the kernel launch
    /// - `lwe_array_out`: output batch of num_samples bootstrapped ciphertexts c =
    /// (a0,..an-1,b) where n is the LWE dimension
    /// - `lut_vector`: should hold as many test vectors of size polynomial_size
    /// as there are input ciphertexts, but actually holds
    /// `num_lut_vectors` vectors to reduce memory usage
    /// - `lut_vector_indexes`: stores the index corresponding to
    /// which test vector to use for each sample in
    /// `lut_vector`
    /// - `lwe_array_in`: input batch of num_samples LWE ciphertexts, containing n
    /// mask values + 1 body value
    /// - `bootstrapping_key`: GGSW encryption of the LWE secret key sk1
    /// under secret key sk2.
    /// bsk = Z + sk1 H
    /// where H is the gadget matrix and Z is a matrix (k+1).l
    /// containing GLWE encryptions of 0 under sk2.
    /// bsk is thus a tensor of size (k+1)^2.l.N.n
    /// where l is the number of decomposition levels and
    /// k is the GLWE dimension, N is the polynomial size for
    /// GLWE. The polynomial size for GLWE and the test vector
    /// are the same because they have to be in the same ring
    /// to be multiplied.
    /// - `pbs_buffer`: a preallocated buffer to store temporary results
    /// - `lwe_dimension`: size of the Torus vector used to encrypt the input
    /// LWE ciphertexts - referred to as n above (~ 600)
    /// - `glwe_dimension`: size of the polynomial vector used to encrypt the LUT
    /// GLWE ciphertexts - referred to as k above. Only the value 1 is supported for this parameter.
    /// - `polynomial_size`: size of the test polynomial (test vector) and size of the
    /// GLWE polynomial (~1024)
    /// - `base_log`: log base used for the gadget matrix - B = 2^base_log (~8)
    /// - `level_count`: number of decomposition levels in the gadget matrix (~4)
    /// - `num_samples`: number of encrypted input messages
    /// - `num_lut_vectors`: parameter to set the actual number of test vectors to be
    /// used
    /// - `lwe_idx`: the index of the LWE input to consider for the GPU of index gpu_index. In
    /// case of multi-GPU computing, it is assumed that only a part of the input LWE array is
    /// copied to each GPU, but the whole LUT array is copied (because the case when the number
    /// of LUTs is smaller than the number of input LWEs is not trivial to take into account in
    /// the data repartition on the GPUs). `lwe_idx` is used to determine which LUT to consider
    /// for a given LWE input in the LUT array `lut_vector`.
    ///  - `max_shared_memory` maximum amount of shared memory to be used inside
    /// device functions
    ///
    /// This function calls a wrapper to a device kernel that performs the
    /// bootstrapping:
    ///   - the kernel is templatized based on integer discretization and
    /// polynomial degree
    ///   - num_samples * level_count * (glwe_dimension + 1) blocks of threads are launched, where
    /// each thread is going to handle one or more polynomial coefficients at each stage,
    /// for a given level of decomposition, either for the LUT mask or its body:
    ///     - perform the blind rotation
    ///     - round the result
    ///     - get the decomposition for the current level
    ///     - switch to the FFT domain
    ///     - multiply with the bootstrapping key
    ///     - come back to the coefficients representation
    ///   - between each stage a synchronization of the threads is necessary (some
    /// synchronizations
    /// happen at the block level, some happen between blocks, using cooperative groups).
    ///   - in case the device has enough shared memory, temporary arrays used for
    /// the different stages (accumulators) are stored into the shared memory
    ///   - the accumulators serve to combine the results for all decomposition
    /// levels
    ///   - the constant memory (64K) is used for storing the roots of identity
    /// values for the FFT
    pub fn cuda_programmable_bootstrap_lwe_ciphertext_vector_64(
        v_stream: *const c_void,
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
        level: u32,
        num_samples: u32,
        num_lut_vectors: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
    );

    /// This cleanup function frees the data for the low latency PBS on GPU
    /// contained in pbs_buffer for 32 or 64-bit inputs.
    pub fn cleanup_cuda_programmable_bootstrap(v_stream: *const c_void, pbs_buffer: *mut *mut i8);

    /// This scratch function allocates the necessary amount of data on the GPU for
    /// the multi-bit PBS on 64-bit inputs into `pbs_buffer`.
    pub fn scratch_cuda_multi_bit_programmable_bootstrap_64(
        v_stream: *const c_void,
        pbs_buffer: *mut *mut i8,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        level_count: u32,
        grouping_factor: u32,
        input_lwe_ciphertext_count: u32,
        max_shared_memory: u32,
        allocate_gpu_memory: bool,
        lwe_chunk_size: u32,
    );

    /// Perform bootstrapping on a batch of input u64 LWE ciphertexts using the multi-bit algorithm.
    ///
    /// - `v_stream` is a void pointer to the Cuda stream to be used in the kernel launch
    /// - `gpu_index` is the index of the GPU to be used in the kernel launch
    /// - `lwe_array_out`: output batch of num_samples bootstrapped ciphertexts c =
    /// (a0,..an-1,b) where n is the LWE dimension
    /// - `lut_vector`: should hold as many test vectors of size polynomial_size
    /// as there are input ciphertexts, but actually holds
    /// `num_lut_vectors` vectors to reduce memory usage
    /// - `lut_vector_indexes`: stores the index corresponding to
    /// which test vector to use for each sample in
    /// `lut_vector`
    /// - `lwe_array_in`: input batch of num_samples LWE ciphertexts, containing n
    /// mask values + 1 body value
    /// - `bootstrapping_key`: GGSW encryption of elements of the LWE secret key as in the
    /// classical PBS, but this time we follow Zhou's trick and encrypt combinations of elements
    /// of the key
    /// - `pbs_buffer`: a preallocated buffer to store temporary results
    /// - `lwe_dimension`: size of the Torus vector used to encrypt the input
    /// LWE ciphertexts - referred to as n above (~ 600)
    /// - `glwe_dimension`: size of the polynomial vector used to encrypt the LUT
    /// GLWE ciphertexts - referred to as k above. Only the value 1 is supported for this parameter.
    /// - `polynomial_size`: size of the test polynomial (test vector) and size of the
    /// GLWE polynomial (~1024)
    /// - `grouping_factor`: number of elements of the LWE secret key combined per GGSW of the
    /// bootstrap key
    /// - `base_log`: log base used for the gadget matrix - B = 2^base_log (~8)
    /// - `level_count`: number of decomposition levels in the gadget matrix (~4)
    /// - `num_samples`: number of encrypted input messages
    /// - `num_lut_vectors`: parameter to set the actual number of test vectors to be
    /// used
    /// - `lwe_idx`: the index of the LWE input to consider for the GPU of index gpu_index. In
    /// case of multi-GPU computing, it is assumed that only a part of the input LWE array is
    /// copied to each GPU, but the whole LUT array is copied (because the case when the number
    /// of LUTs is smaller than the number of input LWEs is not trivial to take into account in
    /// the data repartition on the GPUs). `lwe_idx` is used to determine which LUT to consider
    /// for a given LWE input in the LUT array `lut_vector`.
    ///  - `max_shared_memory` maximum amount of shared memory to be used inside
    /// device functions
    pub fn cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
        v_stream: *const c_void,
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
        grouping_factor: u32,
        base_log: u32,
        level: u32,
        num_samples: u32,
        num_lut_vectors: u32,
        lwe_idx: u32,
        max_shared_memory: u32,
        lwe_chunk_size: u32,
    );

    /// This cleanup function frees the data for the multi-bit PBS on GPU
    /// contained in pbs_buffer for 64-bit inputs.
    pub fn cleanup_cuda_multi_bit_programmable_bootstrap(
        v_stream: *const c_void,
        pbs_buffer: *mut *mut i8,
    );

    /// Perform keyswitch on a batch of 64 bits input LWE ciphertexts.
    ///
    /// - `v_stream` is a void pointer to the Cuda stream to be used in the kernel launch
    /// - `gpu_index` is the index of the GPU to be used in the kernel launch
    /// - `lwe_array_out`: output batch of num_samples keyswitched ciphertexts c =
    /// (a0,..an-1,b) where n is the output LWE dimension (lwe_dimension_out)
    /// - `lwe_array_in`: input batch of num_samples LWE ciphertexts, containing lwe_dimension_in
    /// mask values + 1 body value
    /// - `ksk`: the keyswitch key to be used in the operation
    /// - `base_log`: the log of the base used in the decomposition (should be the one used to
    /// create the ksk).
    /// - `level_count`: the number of levels used in the decomposition (should be the one used to
    /// create the ksk).
    /// - `num_samples`: the number of input and output LWE ciphertexts.
    ///
    /// This function calls a wrapper to a device kernel that performs the keyswitch.
    /// `num_samples` blocks of threads are launched
    pub fn cuda_keyswitch_lwe_ciphertext_vector_64(
        v_stream: *const c_void,
        lwe_array_out: *mut c_void,
        lwe_output_indexes: *const c_void,
        lwe_array_in: *const c_void,
        lwe_input_indexes: *const c_void,
        keyswitch_key: *const c_void,
        input_lwe_dimension: u32,
        output_lwe_dimension: u32,
        base_log: u32,
        level_count: u32,
        num_samples: u32,
    );

    /// Perform the negation of a u64 input LWE ciphertext vector.
    /// - `v_stream` is a void pointer to the Cuda stream to be used in the kernel launch
    /// - `gpu_index` is the index of the GPU to be used in the kernel launch
    /// - `lwe_array_out` is an array of size
    /// `(input_lwe_dimension + 1) * input_lwe_ciphertext_count` that should have been allocated on
    /// the GPU before calling this function, and that will hold the result of the computation.
    /// - `lwe_array_in` is the LWE ciphertext vector used as input, it should have been
    /// allocated and initialized before calling this function. It has the same size as the output
    /// array.
    /// - `input_lwe_dimension` is the number of mask elements in the two input and in the output
    /// ciphertext vectors
    /// - `input_lwe_ciphertext_count` is the number of ciphertexts contained in each input LWE
    /// ciphertext vector, as well as in the output.
    ///
    /// Each element (mask element or body) of the input LWE ciphertext vector is negated.
    /// The result is stored in the output LWE ciphertext vector. The input LWE ciphertext vector
    /// is left unchanged. This function is a wrapper to a device function that performs the
    /// operation on the GPU.
    pub fn cuda_negate_lwe_ciphertext_vector_64(
        v_stream: *const c_void,
        lwe_array_out: *mut c_void,
        lwe_array_in: *const c_void,
        input_lwe_dimension: u32,
        input_lwe_ciphertext_count: u32,
    );

    pub fn cuda_negate_integer_radix_ciphertext_64_inplace(
        v_stream: *const c_void,
        lwe_array: *mut c_void,
        lwe_dimension: u32,
        lwe_ciphertext_count: u32,
        message_modulus: u32,
        carry_modulus: u32,
    );

    /// Perform the addition of two u64 input LWE ciphertext vectors.
    /// - `v_stream` is a void pointer to the Cuda stream to be used in the kernel launch
    /// - `gpu_index` is the index of the GPU to be used in the kernel launch
    /// - `lwe_array_out` is an array of size
    /// `(input_lwe_dimension + 1) * input_lwe_ciphertext_count` that should have been allocated on
    /// the GPU before calling this function, and that will hold the result of the computation.
    /// - `lwe_array_in_1` is the first LWE ciphertext vector used as input, it should have been
    /// allocated and initialized before calling this function. It has the same size as the output
    /// array.
    /// - `lwe_array_in_2` is the second LWE ciphertext vector used as input, it should have been
    /// allocated and initialized before calling this function. It has the same size as the output
    /// array.
    /// - `input_lwe_dimension` is the number of mask elements in the two input and in the output
    /// ciphertext vectors
    /// - `input_lwe_ciphertext_count` is the number of ciphertexts contained in each input LWE
    /// ciphertext vector, as well as in the output.
    ///
    /// Each element (mask element or body) of the input LWE ciphertext vector 1 is added to the
    /// corresponding element in the input LWE ciphertext 2. The result is stored in the output LWE
    /// ciphertext vector. The two input LWE ciphertext vectors are left unchanged. This function is
    /// a wrapper to a device function that performs the operation on the GPU.
    pub fn cuda_add_lwe_ciphertext_vector_64(
        v_stream: *const c_void,
        lwe_array_out: *mut c_void,
        lwe_array_in_1: *const c_void,
        lwe_array_in_2: *const c_void,
        input_lwe_dimension: u32,
        input_lwe_ciphertext_count: u32,
    );

    /// Perform the addition of a u64 input LWE ciphertext vector with a u64 input plaintext vector.
    /// - `v_stream` is a void pointer to the Cuda stream to be used in the kernel launch
    /// - `gpu_index` is the index of the GPU to be used in the kernel launch
    /// - `lwe_array_out` is an array of size
    /// `(input_lwe_dimension + 1) * input_lwe_ciphertext_count` that should have been allocated
    /// on the GPU before calling this function, and that will hold the result of the computation.
    /// - `lwe_array_in` is the LWE ciphertext vector used as input, it should have been
    /// allocated and initialized before calling this function. It has the same size as the output
    /// array.
    /// - `plaintext_array_in` is the plaintext vector used as input, it should have been
    /// allocated and initialized before calling this function. It should be of size
    /// `input_lwe_ciphertext_count`.
    /// - `input_lwe_dimension` is the number of mask elements in the input and output LWE
    /// ciphertext vectors
    /// - `input_lwe_ciphertext_count` is the number of ciphertexts contained in the input LWE
    /// ciphertext vector, as well as in the output. It is also the number of plaintexts in the
    /// input plaintext vector.
    ///
    /// Each plaintext of the input plaintext vector is added to the body of the corresponding LWE
    /// ciphertext in the LWE ciphertext vector. The result of the operation is stored in the output
    /// LWE ciphertext vector. The two input vectors are unchanged. This function is a
    /// wrapper to a device function that performs the operation on the GPU.
    pub fn cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
        v_stream: *const c_void,
        lwe_array_out: *mut c_void,
        lwe_array_in: *const c_void,
        plaintext_array_in: *const c_void,
        input_lwe_dimension: u32,
        input_lwe_ciphertext_count: u32,
    );

    /// Perform the multiplication of a u64 input LWE ciphertext vector with a u64 input cleartext
    /// vector.
    /// - `v_stream` is a void pointer to the Cuda stream to be used in the kernel launch
    /// - `gpu_index` is the index of the GPU to be used in the kernel launch
    /// - `lwe_array_out` is an array of size
    /// `(input_lwe_dimension + 1) * input_lwe_ciphertext_count` that should have been allocated
    /// on the GPU before calling this function, and that will hold the result of the computation.
    /// - `lwe_array_in` is the LWE ciphertext vector used as input, it should have been
    /// allocated and initialized before calling this function. It has the same size as the output
    /// array.
    /// - `cleartext_array_in` is the cleartext vector used as input, it should have been
    /// allocated and initialized before calling this function. It should be of size
    /// `input_lwe_ciphertext_count`.
    /// - `input_lwe_dimension` is the number of mask elements in the input and output LWE
    /// ciphertext vectors
    /// - `input_lwe_ciphertext_count` is the number of ciphertexts contained in the input LWE
    /// ciphertext vector, as well as in the output. It is also the number of cleartexts in the
    /// input cleartext vector.
    ///
    /// Each cleartext of the input cleartext vector is multiplied to the mask and body of the
    /// corresponding LWE ciphertext in the LWE ciphertext vector.
    /// The result of the operation is stored in the output
    /// LWE ciphertext vector. The two input vectors are unchanged. This function is a
    /// wrapper to a device function that performs the operation on the GPU.
    pub fn cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
        v_stream: *const c_void,
        lwe_array_out: *mut c_void,
        lwe_array_in: *const c_void,
        cleartext_array_in: *const c_void,
        input_lwe_dimension: u32,
        input_lwe_ciphertext_count: u32,
    );

    pub fn scratch_cuda_integer_mult_radix_ciphertext_kb_64(
        v_stream: *const c_void,
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
        max_shared_memory: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_integer_mult_radix_ciphertext_kb_64(
        v_stream: *const c_void,
        radix_lwe_out: *mut c_void,
        radix_lwe_left: *const c_void,
        radix_lwe_right: *const c_void,
        bsk: *const c_void,
        ksk: *const c_void,
        mem_ptr: *mut i8,
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
        max_shared_memory: u32,
    );

    pub fn cleanup_cuda_integer_mult(v_stream: *const c_void, mem_ptr: *mut *mut i8);

    pub fn cuda_scalar_addition_integer_radix_ciphertext_64_inplace(
        v_stream: *const c_void,
        lwe_array: *mut c_void,
        scalar_input: *const c_void,
        lwe_dimension: u32,
        lwe_ciphertext_count: u32,
        message_modulus: u32,
        carry_modulus: u32,
    );

    pub fn scratch_cuda_integer_scalar_mul_kb_64(
        v_stream: *const c_void,
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
        v_stream: *const c_void,
        lwe_array: *mut c_void,
        decomposed_scalar: *const u64,
        has_at_least_one_set: *const u64,
        mem: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        lwe_dimension: u32,
        polynomial_size: u32,
        message_modulus: u32,
        num_blocks: u32,
        num_scalars: u32,
    );

    pub fn cleanup_cuda_integer_radix_scalar_mul(v_stream: *const c_void, mem_ptr: *mut *mut i8);

    pub fn scratch_cuda_integer_radix_bitop_kb_64(
        v_stream: *const c_void,
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
        op_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_bitop_integer_radix_ciphertext_kb_64(
        v_stream: *const c_void,
        radix_lwe_out: *mut c_void,
        radix_lwe_left: *const c_void,
        radix_lwe_right: *const c_void,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn cuda_bitnot_integer_radix_ciphertext_kb_64(
        v_stream: *const c_void,
        radix_lwe_out: *mut c_void,
        radix_lwe_in: *const c_void,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn cuda_scalar_bitop_integer_radix_ciphertext_kb_64(
        v_stream: *const c_void,
        radix_lwe_output: *mut c_void,
        radix_lwe_input: *mut c_void,
        clear_blocks: *const c_void,
        num_clear_blocks: u32,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
        op_type: u32,
    );

    pub fn cleanup_cuda_integer_bitop(v_stream: *const c_void, mem_ptr: *mut *mut i8);

    pub fn scratch_cuda_integer_radix_comparison_kb_64(
        v_stream: *const c_void,
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
        op_type: u32,
        is_signed: bool,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_comparison_integer_radix_ciphertext_kb_64(
        v_stream: *const c_void,
        radix_lwe_out: *mut c_void,
        radix_lwe_left: *const c_void,
        radix_lwe_right: *const c_void,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_comparison(v_stream: *const c_void, mem_ptr: *mut *mut i8);

    pub fn cuda_scalar_comparison_integer_radix_ciphertext_kb_64(
        v_stream: *const c_void,
        radix_lwe_out: *mut c_void,
        radix_lwe_in: *const c_void,
        scalar_blocks: *const c_void,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
        num_scalar_blocks: u32,
    );

    pub fn scratch_cuda_full_propagation_64(
        v_stream: *const c_void,
        mem_ptr: *mut *mut i8,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        pbs_level: u32,
        grouping_factor: u32,
        num_blocks: u32,
        message_modulus: u32,
        carry_modulus: u32,
        pbs_type: u32,
        allocate_gpu_memory: bool,
    );

    pub fn cuda_full_propagation_64_inplace(
        v_stream: *const c_void,
        radix_lwe_right: *mut c_void,
        mem_ptr: *mut i8,
        ksk: *const c_void,
        bsk: *const c_void,
        lwe_dimension: u32,
        glwe_dimension: u32,
        polynomial_size: u32,
        ks_base_log: u32,
        ks_level: u32,
        pbs_base_log: u32,
        pbs_level: u32,
        grouping_factor: u32,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_full_propagation(v_stream: *const c_void, mem_ptr: *mut *mut i8);

    pub fn scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
        v_stream: *const c_void,
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
        v_stream: *const c_void,
        radix_lwe: *mut c_void,
        shift: u32,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn scratch_cuda_integer_radix_arithmetic_scalar_shift_kb_64(
        v_stream: *const c_void,
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
        v_stream: *const c_void,
        radix_lwe: *mut c_void,
        shift: u32,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_radix_logical_scalar_shift(
        v_stream: *const c_void,
        mem_ptr: *mut *mut i8,
    );

    pub fn cleanup_cuda_integer_radix_arithmetic_scalar_shift(
        v_stream: *const c_void,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_shift_and_rotate_kb_64(
        v_stream: *const c_void,
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
        v_stream: *const c_void,
        radix_lwe: *mut c_void,
        radix_shift: *const c_void,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_radix_shift_and_rotate(
        v_stream: *const c_void,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_cmux_kb_64(
        v_stream: *const c_void,
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

    pub fn cuda_cmux_integer_radix_ciphertext_kb_64(
        v_stream: *const c_void,
        lwe_array_out: *mut c_void,
        lwe_condition: *const c_void,
        lwe_array_true: *const c_void,
        lwe_array_false: *const c_void,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_radix_cmux(v_stream: *const c_void, mem_ptr: *mut *mut i8);

    pub fn scratch_cuda_integer_radix_scalar_rotate_kb_64(
        v_stream: *const c_void,
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
        v_stream: *const c_void,
        radix_lwe: *mut c_void,
        n: u32,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_radix_scalar_rotate(v_stream: *const c_void, mem_ptr: *mut *mut i8);

    pub fn scratch_cuda_propagate_single_carry_kb_64_inplace(
        v_stream: *const c_void,
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
        v_stream: *const c_void,
        radix_lwe: *mut c_void,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_propagate_single_carry(v_stream: *const c_void, mem_ptr: *mut *mut i8);

    pub fn scratch_cuda_integer_radix_sum_ciphertexts_vec_kb_64(
        v_stream: *const c_void,
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

    pub fn cuda_integer_radix_sum_ciphertexts_vec_kb_64(
        v_stream: *const c_void,
        radix_lwe_out: *mut c_void,
        radix_lwe_vec: *mut c_void,
        num_radix_in_vec: u32,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks_in_radix: u32,
    );

    pub fn cleanup_cuda_integer_radix_sum_ciphertexts_vec(
        v_stream: *const c_void,
        mem_ptr: *mut *mut i8,
    );

    pub fn scratch_cuda_integer_radix_overflowing_sub_kb_64(
        v_stream: *const c_void,
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
        v_stream: *const c_void,
        radix_lwe_out: *mut c_void,
        radix_lwe_overflowed: *mut c_void,
        radix_lwe_left: *const c_void,
        radix_lwe_right: *const c_void,
        mem_ptr: *mut i8,
        bsk: *const c_void,
        ksk: *const c_void,
        num_blocks: u32,
    );

    pub fn cleanup_cuda_integer_radix_overflowing_sub(
        v_stream: *const c_void,
        mem_ptr: *mut *mut i8,
    );

} // extern "C"
