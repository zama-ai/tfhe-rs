import * as pkg from "../../pkg-client/tfhe.js";
import {
  x86CompatBench as runBench,
  x86CompatTest as runTest,
} from "../../shared/zk-from-fixtures.js";

export const x86CompatTest = () => runTest(pkg);
export const x86CompatBench = () => runBench(pkg);
