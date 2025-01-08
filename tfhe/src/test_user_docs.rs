#[cfg(not(feature = "gpu"))]
mod test_cpu_doc {
    use doc_comment::doctest;

    // README
    doctest!("../../README.md", readme);

    // FUNDAMENTALS
    doctest!("../docs/fundamentals/compress.md", fundamentals_compress);
    doctest!("../docs/fundamentals/compute.md", fundamentals_compute);
    doctest!(
        "../docs/fundamentals/configure-and-generate-keys.md",
        fundamentals_configure_and_generate_keys
    );
    doctest!("../docs/fundamentals/debug.md", fundamentals_debug);
    doctest!(
        "../docs/fundamentals/decrypt-data.md",
        fundamentals_decrypt_data
    );
    doctest!(
        "../docs/fundamentals/encrypt-data.md",
        fundamentals_encrypt_data
    );
    doctest!(
        "../docs/fundamentals/encrypted-prf.md",
        fundamentals_encrypted_prf
    );
    doctest!(
        "../docs/fundamentals/serialization.md",
        fundamentals_serialization
    );
    doctest!(
        "../docs/fundamentals/set-the-server-key.md",
        fundamentals_set_the_server_key
    );

    // GETTING STARTED
    doctest!(
        "../docs/getting_started/operations.md",
        getting_started_operations
    );
    doctest!(
        "../docs/getting_started/quick_start.md",
        getting_started_quick_start
    );

    // GUIDES
    doctest!("../docs/guides/array.md", array);
    doctest!(
        "../docs/guides/overflow_operations.md",
        guides_overflow_operations
    );
    doctest!(
        "../docs/guides/parallelized_pbs.md",
        guides_parallelized_pbs
    );
    doctest!("../docs/guides/pbs-stats.md", guides_pbs_stats);
    doctest!("../docs/guides/public_key.md", guides_public_key);
    doctest!("../docs/guides/rayon_crate.md", guides_rayon_crate);
    doctest!("../docs/guides/strings.md", guides_strings);
    doctest!("../docs/guides/trait_bounds.md", guides_trait_bounds);
    doctest!(
        "../docs/guides/trivial_ciphertext.md",
        guides_trivial_ciphertext
    );
    doctest!("../docs/guides/zk-pok.md", guides_zk_pok);
    doctest!("../docs/guides/data_versioning.md", guides_data_versioning);

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

    doctest!("../docs/guides/run_on_gpu.md", guides_run_on_gpu);
}
