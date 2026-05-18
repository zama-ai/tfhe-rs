export const U32_MAX = 4294967295;
export const U64_MAX = BigInt("0xffffffffffffffff");
export const SIZE_LIMIT = BigInt(10_000_000);
export const SIZE_LIMIT_LARGE = BigInt(1_000_000_000);

// 320 bits is a use case we have, 8 bits per byte
export const ZK_METADATA_BYTES = 320 / 8;

export function assert(cond, text) {
  if (cond) return;
  if (console.assert.useDebugger) debugger;
  throw new Error(text || "Assertion failed!");
}

export function assertEq(a, b, text) {
  if (a === b) return;
  if (console.assert.useDebugger) debugger;
  throw new Error(text || `Equality assertion failed!: ${a} != ${b}`);
}

export function generateRandomBigInt(bitLen) {
  let result = BigInt(0);
  for (let i = 0; i < bitLen; i++) {
    result <<= 1n;
    result |= BigInt(Math.random() < 0.5);
  }
  return result;
}

export function generateMetadata() {
  const metadata = new Uint8Array(ZK_METADATA_BYTES);
  crypto.getRandomValues(metadata);
  return metadata;
}

/**
 * Measure the average wall-clock time of `fn` over `loops` iterations.
 * Defaults to 1 iteration when no loop count is needed.
 * Works transparently for sync and async functions.
 * @param {() => any | Promise<any>} fn - The function to measure.
 * @param {number} loops - Number of iterations (default 1).
 * @returns {Promise<number>} Average time per iteration in ms.
 */
export async function bench(fn, loops = 1) {
  const start = performance.now();
  for (let i = 0; i < loops; i++) {
    await fn();
  }
  const end = performance.now();
  return (end - start) / loops;
}
