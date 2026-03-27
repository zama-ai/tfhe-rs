#!/usr/bin/env python3
# This script aggregates multi-process-group benchmark results
# that are obtained by running benchmarks in a multi-process approach
import argparse
import json
import sys

ACCEPTED_TEST_PREFIX = "tfhe::hlapi::erc7984::transfer"


# Looks at the Slab JSON benchmark results and aggregates the "value" field.
# For throughput, values are summed across groups.
# For latency, values are averaged across groups.
def merge_multi_group_results(input_files, output_file, bench_type):
    accumulated = {}
    counts = {}
    metadata = None

    for path in input_files:
        with open(path) as f:
            data = json.load(f)
        if metadata is None:
            metadata = {k: v for k, v in data.items() if k != "points"}
        for point in data["points"]:
            test = point["test"]
            if "_std_dev" in test:
                continue
            if not test.startswith(ACCEPTED_TEST_PREFIX):
                print(
                    f"Error: unexpected test '{test}' in {path}: this script only "
                    f"supports aggregation of '{ACCEPTED_TEST_PREFIX}' results",
                    file=sys.stderr,
                )
                sys.exit(1)
            point_type = point["type"]
            if point_type.lower() != bench_type:
                print(
                    f"Error: point '{test}' in {path} holds a {point_type} measurement "
                    f"but --bench-type is {bench_type}",
                    file=sys.stderr,
                )
                sys.exit(1)
            if test in accumulated:
                accumulated[test]["value"] += point["value"]
                counts[test] += 1
            else:
                accumulated[test] = dict(point)
                counts[test] = 1

    if bench_type == "latency":
        for test in accumulated:
            accumulated[test]["value"] /= counts[test]

    for test, point in accumulated.items():
        print(f"merged {bench_type} over {counts[test]} groups: {test} = {point['value']:.1f}")

    result = dict(metadata)
    result["points"] = list(accumulated.values())

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)


# The output is a positional argument, for file names we accept 2+
parser = argparse.ArgumentParser()
parser.add_argument("input_files", nargs="+")
parser.add_argument("--output", required=True)
parser.add_argument("--bench-type", required=True, choices=["throughput", "latency"])

if __name__ == "__main__":
    args = parser.parse_args()
    if len(args.input_files) < 2:
        print("Error: at least 2 input files required", file=sys.stderr)
        sys.exit(1)
    merge_multi_group_results(args.input_files, args.output, args.bench_type)
