#[cfg(not(any(feature = "gpu", feature = "hpu")))]
mod test_cpu_doc {
    use doc_comment::doctest;

    // README
    doctest!("../../README.md", readme);

    // CONGFIGURATION
    doctest!(
        "../docs/configuration/parallelized_pbs.md",
        configuration_parallelized_pbs
    );
    doctest!(
        "../docs/configuration/rust_configuration.md",
        configuration_rust_configuration
    );

    // FHE COMPUTATION

    // ADVANCED FEATURES
    doctest!(
        "../docs/fhe-computation/advanced-features/encrypted-prf.md",
        advanced_features_encrypted_prf
    );
    doctest!(
        "../docs/fhe-computation/advanced-features/overflow_operations.md",
        advanced_features_overflow_operations
    );
    doctest!(
        "../docs/fhe-computation/advanced-features/public_key.md",
        advanced_features_public_key
    );
    doctest!(
        "../docs/fhe-computation/advanced-features/rayon_crate.md",
        advanced_features_rayon_crate
    );
    doctest!(
        "../docs/fhe-computation/advanced-features/trivial_ciphertext.md",
        advanced_features_trivial_ciphertext
    );
    doctest!(
        "../docs/fhe-computation/advanced-features/zk-pok.md",
        advanced_features_zk_pok
    );

    // COMPUTE
    doctest!(
        "../docs/fhe-computation/compute/configure-and-generate-keys.md",
        compute_configure_and_generate_keys
    );
    doctest!(
        "../docs/fhe-computation/compute/decrypt-data.md",
        compute_decrypt_data
    );
    doctest!(
        "../docs/fhe-computation/compute/encrypt-data.md",
        compute_encrypt_data
    );
    doctest!("../docs/fhe-computation/compute/README.md", compute_readme);
    doctest!(
        "../docs/fhe-computation/compute/set-the-server-key.md",
        compute_set_the_server_key
    );
    doctest!(
        "../docs/fhe-computation/compute/parameters.md",
        compute_parameters
    );

    // DATA HANDLING
    doctest!(
        "../docs/fhe-computation/data-handling/compress.md",
        data_handling_compress
    );
    doctest!(
        "../docs/fhe-computation/data-handling/data_versioning.md",
        data_handling_data_versioning
    );
    doctest!(
        "../docs/fhe-computation/data-handling/serialization.md",
        data_handling_serialization
    );

    // OPERATIONS
    doctest!(
        "../docs/fhe-computation/operations/arithmetic-operations.md",
        operations_arithmetic_operations
    );
    doctest!(
        "../docs/fhe-computation/operations/bitwise-operations.md",
        operations_bitwise_operations
    );
    doctest!(
        "../docs/fhe-computation/operations/casting-operations.md",
        operations_casting_operations
    );
    doctest!(
        "../docs/fhe-computation/operations/comparison-operations.md",
        operations_comparison_operations
    );
    doctest!(
        "../docs/fhe-computation/operations/min-max-operations.md",
        operations_min_max_operations
    );
    doctest!(
        "../docs/fhe-computation/operations/ternary-conditional-operations.md",
        operations_ternary_conditional_operations
    );
    doctest!(
        "../docs/fhe-computation/operations/string-operations.md",
        operations_string_operations
    );
    doctest!(
        "../docs/fhe-computation/operations/dot-product.md",
        operations_dot_product
    );

    // TOOLING
    doctest!("../docs/fhe-computation/tooling/debug.md", tooling_debug);
    doctest!(
        "../docs/fhe-computation/tooling/pbs-stats.md",
        tooling_pbs_stats
    );
    doctest!(
        "../docs/fhe-computation/tooling/trait_bounds.md",
        tooling_trait_bounds
    );

    // TYPES
    doctest!("../docs/fhe-computation/types/array.md", types_array);
    doctest!("../docs/fhe-computation/types/strings.md", types_strings);

    // GETTING STARTED
    doctest!(
        "../docs/getting_started/quick_start.md",
        getting_started_quick_start
    );

    // REFERENCES

    // FINE GRAINED API
    doctest!(
        "../docs/references/fine-grained-apis/quick_start.md",
        references_fine_grained_apis_quick_start
    );

    // fine-grained-apis/boolean
    doctest!(
        "../docs/references/fine-grained-apis/boolean/operations.md",
        references_fine_grained_apis_boolean_operations
    );
    doctest!(
        "../docs/references/fine-grained-apis/boolean/parameters.md",
        references_fine_grained_apis_boolean_parameters
    );
    doctest!(
        "../docs/references/fine-grained-apis/boolean/serialization.md",
        references_fine_grained_apis_boolean_serialization
    );
    doctest!(
        "../docs/references/fine-grained-apis/boolean/README.md",
        references_fine_grained_apis_boolean_readme
    );

    // fine-grained-apis/shortint
    doctest!(
        "../docs/references/fine-grained-apis/shortint/operations.md",
        references_fine_grained_apis_shortint_operations
    );
    doctest!(
        "../docs/references/fine-grained-apis/shortint/parameters.md",
        references_fine_grained_apis_shortint_parameters
    );
    doctest!(
        "../docs/references/fine-grained-apis/shortint/serialization.md",
        references_fine_grained_apis_shortint_serialization
    );
    doctest!(
        "../docs/references/fine-grained-apis/shortint/README.md",
        references_fine_grained_apis_shortint_readme
    );

    // fine-grained-apis/integer
    doctest!(
        "../docs/references/fine-grained-apis/integer/operations.md",
        references_fine_grained_apis_integer_operations
    );
    doctest!(
        "../docs/references/fine-grained-apis/integer/serialization.md",
        references_fine_grained_apis_integer_serialization_tuto
    );
    doctest!(
        "../docs/references/fine-grained-apis/integer/README.md",
        references_fine_grained_apis_integer_readme
    );

    // references/core-crypto-api
    doctest!(
        "../docs/references/core-crypto-api/presentation.md",
        references_core_crypto_api_presentation
    );
    doctest!(
        "../docs/references/core-crypto-api/tutorial.md",
        references_core_crypto_api_tutorial
    );

    // Tutorials
    doctest!(
        "../docs/tutorials/ascii_fhe_string.md",
        tutorials_ascii_fhe_string
    );
    doctest!("../docs/tutorials/parity_bit.md", tutorials_parity_bit);
}

#[cfg(feature = "gpu")]
mod test_gpu_doc {
    use doc_comment::doctest;

    doctest!(
        "../docs/configuration/gpu_acceleration/run_on_gpu.md",
        configuration_gpu_acceleration_run_on_gpu
    );
    doctest!(
        "../docs/configuration/gpu_acceleration/gpu_operations.md",
        configuration_gpu_acceleration_gpu_operations
    );
    doctest!(
        "../docs/configuration/gpu_acceleration/compressing_ciphertexts.md",
        configuration_gpu_acceleration_compressing_ciphertexts
    );
    doctest!(
        "../docs/configuration/gpu_acceleration/array_type.md",
        configuration_gpu_acceleration_array_type
    );
    doctest!(
        "../docs/configuration/gpu_acceleration/benchmark.md",
        configuration_gpu_acceleration_benchmark
    );
    doctest!(
        "../docs/configuration/gpu_acceleration/multi_gpu.md",
        configuration_gpu_acceleration_multi_gpu_device_selection
    );
    doctest!(
        "../docs/configuration/gpu_acceleration/zk-pok.md",
        configuration_gpu_acceleration_zk_pok
    );
}

#[cfg(feature = "hpu")]
mod test_hpu_doc {
    use doc_comment::doctest;

    doctest!(
        "../docs/configuration/hpu_acceleration/run_on_hpu.md",
        configuration_hpu_acceleration_run_on_hpu
    );
}
