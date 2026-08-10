#!/usr/bin/env python3
# Slab silently starts a fallback profile when the requested one is unavailable, so the requested
# hardware name may describe a machine we never got. Rename it after the GPUs nvidia-smi reports.
import argparse
import json
import pathlib
import sys

TABLE_PATH = pathlib.Path(__file__).with_name("gpu_hardware.json")


def load_hardware():
    """
    Read gpu_hardware.json: GPU count and model keyed by instance_type (aws, terraform) or
    flavor_name (hyperstack), grouped by provider.

    :return: flattened table as {hardware name: (GPU count, model)}
    """
    return {
        name: (spec["count"], spec.get("model", ""))
        for profiles in json.loads(TABLE_PATH.read_text()).values()
        for name, spec in profiles.items()
    }


def warn(message):
    print(f"Warning: {message}", file=sys.stderr)


def resolve(requested, gpu_names, hardware):
    models = sorted(set(gpu_names))
    observed = f"{len(gpu_names)} x {', '.join(models) or 'no GPU'}"
    print(f"Detected {observed}", flush=True)

    if requested not in hardware:
        sys.exit(f"Error: unknown hardware '{requested}', add it to {TABLE_PATH.name}.")

    def matches(name):
        count, model = hardware[name]
        return count == len(gpu_names) and all(model in observed_model for observed_model in models)

    if matches(requested):
        return requested

    candidates = [name for name in hardware if matches(name)]
    if len(candidates) == 1:
        warn(f"requested {requested}, got a {candidates[0]}: Slab fell back.")
        return candidates[0]

    if hardware[requested][0] == len(gpu_names):
        warn(f"requested {requested}, got {observed}: keeping {requested}.")
        return requested

    raise SystemExit(
        f"Error: no hardware in {TABLE_PATH.name} has {observed} (requested {requested})."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Resolve the hardware name describing the machine a benchmark runs on."
    )
    parser.add_argument("--requested", required=True, help="hardware name of the requested profile")
    parser.add_argument("--gpu-info", required=True, help="file with one GPU name per line")
    parser.add_argument(
        "--output", required=True, help="file to append HARDWARE_NAME and NUM_GROUPS to"
    )
    args = parser.parse_args()

    with open(args.gpu_info) as f:
        gpu_names = [line.strip() for line in f if line.strip()]

    resolved = resolve(args.requested, gpu_names, load_hardware())

    print(f"Sending results under hardware name: {resolved}", flush=True)
    with open(args.output, "a") as f:
        f.write(f"HARDWARE_NAME={resolved}\nNUM_GROUPS={len(gpu_names)}\n")


if __name__ == "__main__":
    main()
