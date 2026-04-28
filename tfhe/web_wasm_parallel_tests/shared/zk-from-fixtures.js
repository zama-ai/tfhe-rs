import { bench, SIZE_LIMIT_LARGE } from "./helper.js";

const FIXTURES_URL_BASE = "/fixtures";
// Must match the METADATA constant in `tfhe/tests/zk_wasm_x86_test.rs`.
const METADATA_STR = "wasm64";

function metadataBytes() {
  return Uint8Array.from(METADATA_STR.split("").map((c) => c.charCodeAt(0)));
}

/**
 * Fetch + deserialize the public key and CRS fixtures.
 * @param {object} pkg - wasm pkg namespace (must expose
 *   `TfheCompactPublicKey` and `CompactPkeCrs`).
 */
export async function loadFixtures(pkg) {
  const [pkResp, crsResp] = await Promise.all([
    fetch(`${FIXTURES_URL_BASE}/public_key.bin`),
    fetch(`${FIXTURES_URL_BASE}/crs.bin`),
  ]);
  if (!pkResp.ok) {
    throw new Error(
      `Failed to fetch public_key.bin (${pkResp.status}). Run \`make test_zk_wasm_x86_compat\` to generate fixtures, then rebuild.`,
    );
  }
  if (!crsResp.ok) {
    throw new Error(`Failed to fetch crs.bin (${crsResp.status}).`);
  }

  const [pkBuf, crsBuf] = await Promise.all([
    pkResp.arrayBuffer(),
    crsResp.arrayBuffer(),
  ]);

  const publicKey = pkg.TfheCompactPublicKey.safe_deserialize(
    new Uint8Array(pkBuf),
    SIZE_LIMIT_LARGE,
  );
  const crs = pkg.CompactPkeCrs.safe_deserialize(
    new Uint8Array(crsBuf),
    SIZE_LIMIT_LARGE,
  );

  return { publicKey, crs };
}

/**
 * Run the encrypt + ZK proof flow `loops` times using the provided fixtures,
 * pushing the same u4 + u8 payload as the x86 compat test.
 * @returns {Promise<{ timing_ms: number, serialized_size: number }>}
 *   timing_ms = average per iteration in ms.
 *   serialized_size = size of the proven ciphertext list in bytes.
 */
export async function runFixturesProof(pkg, { publicKey, crs, loops = 1 }) {
  const { CompactCiphertextList, ZkComputeLoad } = pkg;
  const metadata = metadataBytes();

  let serialized_size = 0;
  const timing_ms = await bench(() => {
    const builder = CompactCiphertextList.builder(publicKey);
    builder.push_u4(1);
    builder.push_u8(0xff);
    const encrypted = builder.build_with_proof_packed(
      crs,
      metadata,
      ZkComputeLoad.Proof,
    );
    serialized_size = encrypted.safe_serialize(SIZE_LIMIT_LARGE).length;
  }, loops);

  return { timing_ms, serialized_size };
}

/**
 * Convenience: load fixtures + run a single encrypt+prove. Reused by both
 * the full and the client tests; only the wasm pkg differs at the call site.
 */
export async function x86CompatTest(pkg) {
  const { publicKey, crs } = await loadFixtures(pkg);
  const r = await runFixturesProof(pkg, { publicKey, crs });
  console.log(`x86 compat encrypt+prove: ${r.timing_ms.toFixed(2)} ms`);
  console.log(`Proof size: ${r.serialized_size} bytes`);
  return r;
}

/**
 * Convenience: load fixtures + run an N-loop bench. Returns a result object
 * with the bench keys the parser expects.
 */
export async function x86CompatBench(pkg, loops = 5) {
  const { publicKey, crs } = await loadFixtures(pkg);
  const r = await runFixturesProof(pkg, { publicKey, crs, loops });
  console.log(
    `x86 compat encrypt+prove (${loops} loops avg): ${r.timing_ms.toFixed(2)} ms`,
  );
  return {
    zk_x86_compat_mean: r.timing_ms,
    zk_x86_compat_serialized_size: r.serialized_size,
  };
}
