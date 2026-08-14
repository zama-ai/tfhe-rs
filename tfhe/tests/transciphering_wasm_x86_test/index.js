const {
  OneTimePadPlainSecretMask,
  OneTimePadPlainState,
  FheTypes,
} = require("node-tfhe");

const fs = require("fs");

const SIZE_LIMIT = BigInt(1024) * BigInt(1024) * BigInt(1024);

// Kept in sync with transciphering_wasm_x86_test.rs
const CLEAR_A = 0xdeadbeefcafebaben;
const CLEAR_B = 0x0a5cn;
const CLEAR_C = true;

const transcipher_inputs = () => {
  const padBuf = fs.readFileSync(`${__dirname}/pad.bin`);
  const mask = OneTimePadPlainSecretMask.safe_deserialize(padBuf, SIZE_LIMIT);

  // The three inputs are drawn from the one pad, in order: the server has to
  // replay the same offsets on the FHE side.
  const state = new OneTimePadPlainState(mask);
  const encA = state.encrypt(CLEAR_A, FheTypes.Uint64);
  const encB = state.encrypt(CLEAR_B, FheTypes.Uint12);
  const encC = state.encrypt(CLEAR_C, FheTypes.Bool);

  fs.writeFileSync(
    `${__dirname}/input_a.bin`,
    Buffer.from(encA.safe_serialize(SIZE_LIMIT)),
  );
  fs.writeFileSync(
    `${__dirname}/input_b.bin`,
    Buffer.from(encB.safe_serialize(SIZE_LIMIT)),
  );
  fs.writeFileSync(
    `${__dirname}/input_c.bin`,
    Buffer.from(encC.safe_serialize(SIZE_LIMIT)),
  );
};

transcipher_inputs();
