use doc_comment::doctest;

doctest!("../docs/getting_started/first_circuit.md", first_circuit);
doctest!("../docs/tutorials/serialization.md", serialization_tuto);
doctest!(
    "../docs/tutorials/circuit_evaluation.md",
    circuit_evaluation
);
doctest!("../docs/how_to/pbs.md", pbs);
