import {
  fixtureEncryptProveBench as runBench,
  fixtureEncryptProveTest as runTest,
} from "./zk-from-fixtures.js";

// Shared by the full and client builds, only the pkg differs.
export const makeFixtureDemos = (pkg) => ({
  fixtureEncryptProveTest: () => runTest(pkg),
  fixtureEncryptProveBench: () => runBench(pkg),
});
