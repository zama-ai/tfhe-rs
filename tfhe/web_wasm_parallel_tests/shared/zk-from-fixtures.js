import { bench, SIZE_LIMIT_LARGE } from "./helper.js";

const FIXTURES_URL_BASE = "/fixtures";
// Must match the METADATA constant in `tfhe/tests/zk_wasm_x86_test.rs`.
const METADATA_STR = "wasm64";

function metadataBytes() {
  return Uint8Array.from(METADATA_STR.split("").map((c) => c.charCodeAt(0)));
}

/**
 * base64-encode a Uint8Array. Chunked to stay clear of the argument-count
 * limit of `String.fromCharCode` on large buffers.
 */
function bytesToBase64(bytes) {
  const CHUNK = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
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
      `Failed to fetch public_key.bin (${pkResp.status}). Run \`make prepare_fixtures\` (in tfhe/web_wasm_parallel_tests/) to generate and serve them.`,
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
 * pushing a small u4 + u8 payload (same shape as the Rust test fixture).
 * @returns {Promise<{ timing_ms: number, serialized_size: number, serialized: Uint8Array }>}
 *   timing_ms = average per iteration in ms.
 *   serialized_size = size of the proven ciphertext list in bytes.
 *   serialized = serialized proven ciphertext list of the last iteration
 *     (reused by the x86 compat check to verify the proof on the Rust side).
 */
export async function runFixturesProof(pkg, { publicKey, crs, loops = 1 }) {
  const { CompactCiphertextList, ZkComputeLoad } = pkg;
  const metadata = metadataBytes();

  let serialized = new Uint8Array(0);
  const timing_ms = await bench(() => {
    const builder = CompactCiphertextList.builder(publicKey);
    builder.push_u4(1);
    builder.push_u8(0xff);
    const encrypted = builder.build_with_proof_packed(
      crs,
      metadata,
      ZkComputeLoad.Proof,
    );
    serialized = encrypted.safe_serialize(SIZE_LIMIT_LARGE);
  }, loops);

  return { timing_ms, serialized_size: serialized.length, serialized };
}

/**
 * Smoke test: load fixtures + run a single encrypt+prove. Reused by both
 * the full and the client tests; only the wasm pkg differs at the call site.
 *
 * Returns `proof_b64`, the base64 of the proven ciphertext list, so the
 * selenium runner can capture it (`--capture-key proof_b64`) and hand it to
 * the Rust `verify_zk_wasm_proof` test for x86 cross-verification.
 */
export async function fixtureEncryptProveTest(pkg) {
  const { publicKey, crs } = await loadFixtures(pkg);
  const r = await runFixturesProof(pkg, { publicKey, crs });
  console.log(`Encrypt+prove (from fixture): ${r.timing_ms.toFixed(2)} ms`);
  console.log(`Proof size: ${r.serialized_size} bytes`);
  return {
    timing_ms: r.timing_ms,
    serialized_size: r.serialized_size,
    proof_b64: bytesToBase64(r.serialized),
  };
}

/**
 * Benchmark: load fixtures + run an N-loop encrypt+prove. Returns a result
 * object compatible with the bench-results parser.
 */
export async function fixtureEncryptProveBench(pkg, loops = 5) {
  const { publicKey, crs } = await loadFixtures(pkg);
  const r = await runFixturesProof(pkg, { publicKey, crs, loops });
  console.log(
    `Encrypt+prove (from fixture, ${loops} loops avg): ${r.timing_ms.toFixed(2)} ms`,
  );
  return {
    fixture_encrypt_prove_mean: r.timing_ms,
    fixture_encrypt_prove_serialized_size: r.serialized_size,
  };
}
