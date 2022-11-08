use doc_comment::doctest;

// Getting started
doctest!("../docs/getting_started/quick_start.md", quick_start);
doctest!("../docs/getting_started/operations.md", operations);

// Booleans
doctest!("../docs/Booleans/parameters.md", booleans_parameters);
doctest!("../docs/Booleans/operations.md", booleans_operations);
doctest!("../docs/Booleans/serialization.md", booleans_serialization);
doctest!("../docs/Booleans/tutorial.md", booleans_tutorial);

// Shortint
doctest!("../docs/shortint/parameters.md", shortint_parameters);
doctest!("../docs/shortint/serialization.md", shortint_serialization);
doctest!("../docs/shortint/tutorial.md", shortint_tutorial);
doctest!("../docs/shortint/operations.md", shortint_operations);

// doctest!("../docs/tutorials/serialization.md", serialization_tuto);
// doctest!(
//     "../docs/tutorials/circuit_evaluation.md",
//     circuit_evaluation
// );
