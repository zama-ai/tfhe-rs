use doc_comment::doctest;

// Getting started
doctest!("../docs/getting_started/quick_start.md", quick_start);
doctest!("../docs/getting_started/operations.md", operations);

// Booleans
doctest!("../docs/Boolean/parameters.md", booleans_parameters);
doctest!("../docs/Boolean/operations.md", booleans_operations);
doctest!("../docs/Boolean/serialization.md", booleans_serialization);
doctest!("../docs/Boolean/tutorial.md", booleans_tutorial);

// Shortint
doctest!("../docs/shortint/parameters.md", shortint_parameters);
doctest!("../docs/shortint/serialization.md", shortint_serialization);
doctest!("../docs/shortint/tutorial.md", shortint_tutorial);
doctest!("../docs/shortint/operations.md", shortint_operations);

// core_crypto
doctest!(
    "../docs/core_crypto/presentation.md",
    core_crypto_presentation
);
doctest!("../docs/core_crypto/tutorial.md", core_crypto_turorial);

// doctest!("../docs/tutorials/serialization.md", serialization_tuto);
// doctest!(
//     "../docs/tutorials/circuit_evaluation.md",
//     circuit_evaluation
// );
