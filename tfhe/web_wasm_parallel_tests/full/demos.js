import { makePublicKeyDemos } from "./tests/public-key.js";
import { makeCompactKeyDemos } from "./tests/compact-key.js";
import { makeZkDemos } from "./tests/zk.js";
import { makeFixtureDemos } from "../shared/fixture-demos.js";
import { makeCompactKeyBenches } from "./benches/compact-key.js";
import { makeServerKeyBenches } from "./benches/server-key.js";
import { makeZkBenches } from "./benches/zk.js";

// `asyncMainThread*` is excluded: it runs on the main thread, not the worker.
export function makeFullDemos(pkg) {
  const { asyncMainThreadCompactPublicKeyZeroKnowledgeTest, ...zkWorkerDemos } =
    makeZkDemos(pkg);
  return {
    ...makePublicKeyDemos(pkg),
    ...makeCompactKeyDemos(pkg),
    ...zkWorkerDemos,
    ...makeFixtureDemos(pkg),
    ...makeCompactKeyBenches(pkg),
    ...makeServerKeyBenches(pkg),
    ...makeZkBenches(pkg),
  };
}
