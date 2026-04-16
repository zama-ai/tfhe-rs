#!/usr/bin/env python3
# This script aggregates multi-process-group benchmark results
# that are obtained by running benchmarks in a multi-process approach
import argparse
import json
import sys

ACCEPTED_TEST_PREFIXES = [
    "hlapi::cuda::erc7984::throughput",
]


# Looks at the Slab JSON benchmark results, accumulates the "value" field
# which contains the measurement. This script will only accept to
# aggregate throughput results of the ACCEPTED benchmarks.
def merge_multi_group_results(input_files, output_file):
    accumulated = {}
    metadata = None

    for path in input_files:
        with open(path) as f:
            data = json.load(f)
        if metadata is None:
            metadata = {k: v for k, v in data.items() if k != "points"}
        for point in data["points"]:
            test = point["test"]
            if not any(test.startswith(prefix) for prefix in ACCEPTED_TEST_PREFIXES):
                print(
                    f"Error: unexpected test '{test}' in {path}: "
                    f"this script only supports aggregation of: {ACCEPTED_TEST_PREFIXES}",
                    file=sys.stderr,
                )
                sys.exit(1)
            if test in accumulated:
                accumulated[test]["value"] += point["value"]
            else:
                accumulated[test] = dict(point)

    result = dict(metadata)
    result["points"] = list(accumulated.values())

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)


# The output is a positional argument, for file names we accept 2+
parser = argparse.ArgumentParser()
parser.add_argument("input_files", nargs="+")
parser.add_argument("--output", required=True)

if __name__ == "__main__":
    args = parser.parse_args()
    if len(args.input_files) < 2:
        print("Error: at least 2 input files required", file=sys.stderr)
        sys.exit(1)
    merge_multi_group_results(args.input_files, args.output)
