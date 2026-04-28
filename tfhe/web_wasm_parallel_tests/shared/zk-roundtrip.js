import { assertEq, bench, SIZE_LIMIT } from "./helper.js";

/**
 * Run the full ZK proof round-trip for a set of u64 inputs:
 *   1. Build a CompactCiphertextList, push inputs, build_with_proof_packed
 *   2. Round-trip the serialization
 *   3. verify_and_expand against the CRS, decrypt, assert
 *   4. (optional) Also test expand_without_verification + decrypt + assert
 *
 * @param {object} args
 * @param {object} args.pkg - The wasm pkg namespace (full or client).
 *   Must expose `CompactCiphertextList`, `ProvenCompactCiphertextList`,
 *   `ZkComputeLoad`. The pkg is passed in (not imported here) so the same
 *   helper works against both the full and the client builds.
 * @returns {Promise<{ timing_ms: number, serialized_size: number }>}
 *   timing_ms: time to build + prove (excludes serialization).
 *   serialized_size: size of the proven ciphertext list in bytes.
 */
export async function runZkProofRoundtrip({
  pkg,
  clientKey,
  publicKey,
  crs,
  metadata,
  inputs,
  asyncProof = false,
  loadChoice,
  alsoTestUnverifiedExpand = false,
}) {
  const { CompactCiphertextList, ProvenCompactCiphertextList, ZkComputeLoad } =
    pkg;
  const effectiveLoadChoice = loadChoice ?? ZkComputeLoad.Proof;

  let list;
  const timing_ms = await bench(async () => {
    const builder = CompactCiphertextList.builder(publicKey);
    for (const input of inputs) {
      builder.push_u64(input);
    }
    list = asyncProof
      ? await builder.build_with_proof_packed_async(
          crs,
          metadata,
          effectiveLoadChoice,
        )
      : builder.build_with_proof_packed(crs, metadata, effectiveLoadChoice);
  });

  const serialized = list.safe_serialize(SIZE_LIMIT);
  const deserialized = ProvenCompactCiphertextList.safe_deserialize(
    serialized,
    SIZE_LIMIT,
  );

  const expander = deserialized.verify_and_expand(crs, publicKey, metadata);
  for (let i = 0; i < inputs.length; i++) {
    assertEq(expander.get_uint64(i).decrypt(clientKey), inputs[i]);
  }

  if (alsoTestUnverifiedExpand) {
    const unverified = deserialized.expand_without_verification();
    for (let i = 0; i < inputs.length; i++) {
      assertEq(unverified.get_uint64(i).decrypt(clientKey), inputs[i]);
    }
  }

  return { timing_ms, serialized_size: serialized.length };
}
