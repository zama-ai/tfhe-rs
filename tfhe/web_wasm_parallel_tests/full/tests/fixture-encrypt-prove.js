import * as pkg from "../../pkg/tfhe.js";
import {
  fixtureEncryptProveBench as runBench,
  fixtureEncryptProveTest as runTest,
} from "../../shared/zk-from-fixtures.js";

export const fixtureEncryptProveTest = () => runTest(pkg);
export const fixtureEncryptProveBench = () => runBench(pkg);
