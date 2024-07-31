# Zero-knowledge proof benchmarks

This document details the performance benchmarks of [zero-knowledge proofs](../../guides/zk-pok.md) for homomorphic operations using **TFHE-rs**.

Benchmarks for the zero-knowledge proofs have been run on a `m6i.4xlarge` with 16 cores to simulate an usual client configuration.  The verification are done on a `hpc7a.96xlarge` AWS instances to mimic a powerful server. 

Timings in the case where the workload is mainly on the prover, i.e., with the  `ZkComputeLoad::Proof` option.

| Inputs       | Proving | Verifying |
|--------------|---------|-----------|
| 1xFheUint64  | 2.79s   | 197ms     |
| 10xFheUint64 | 3.68s   | 251ms     |
 

Timings in the case where the workload is mainly on the verifier, i.e., with the  `ZkComputeLoad::Verify` option.

| Inputs       | Proving | Verifying |
|--------------|---------|-----------|
| 1xFheUint64  | 730ms   | 522ms     |
| 10xFheUint64 | 1.08s   | 682ms     |
