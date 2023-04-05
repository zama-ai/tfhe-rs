use doc_comment::doctest;

// readme
doctest!("../../README.md", readme);

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

// Integer
doctest!("../docs/integer/tutorial.md", integer_first_circuit);
doctest!(
    "../docs/integer/serialization.md",
    integer_serialization_tuto
);
doctest!(
    "../docs/integer/tutorials/circuit_evaluation.md",
    integer_circuit_evaluation
);
doctest!("../docs/integer/how_to/pbs.md", integer_pbs);

// typed_api
doctest!("../docs/typed_api/tutorial.md", typed_api_first_circuit);
doctest!("../docs/typed_api/operations.md", typed_api_operations);
doctest!(
    "../docs/typed_api/serialization.md",
    typed_api_serialization_tuto
);
doctest!(
    "../docs/typed_api/tutorials/parity_bit.md",
    typed_api_parity_bit
);
doctest!(
    "../docs/typed_api/tutorials/latin_string.md",
    typed_api_latin_string
);
