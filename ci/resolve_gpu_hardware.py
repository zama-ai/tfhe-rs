#!/usr/bin/env python3
# Name the machine a benchmark actually runs on: Slab falls back to another profile when the
# requested one is unavailable, so the requested hardware name can describe a machine we never
# got. Compare the GPUs nvidia-smi reports against the table below and rename when they differ.
# The table is copied from the Slab config: the runner's Python 3.10 has no tomllib.
import argparse
import sys

TABLE_PATH = "ci/resolve_gpu_hardware.py"

# GPU composition of every hardware name, keyed by profile instance_type (aws, terraform) or
# flavor_name (hyperstack). "model" only tells apart hardware with the same GPU count.
HARDWARE = {
    # aws
    "m6i.32xlarge": {"count": 0},
    "m6i.4xlarge": {"count": 0},
    "hpc7a.96xlarge": {"count": 0},
    "hpc8a.96xlarge": {"count": 0},
    "p5.4xlarge": {"count": 1, "model": "H100 80GB HBM3"},
    "g6e.24xlarge": {"count": 4, "model": "L40S"},
    "g6.2xlarge": {"count": 1, "model": "NVIDIA L4"},
    # hyperstack
    "n3-L40x1": {"count": 1, "model": "NVIDIA L40"},
    "n3-L40x4": {"count": 4, "model": "NVIDIA L40"},
    "n3-L40x8": {"count": 8, "model": "NVIDIA L40"},
    "n3-RTX-A6000x1": {"count": 1, "model": "RTX A6000"},
    "n3-RTX-A4000x4": {"count": 4, "model": "RTX A4000"},
    "n3-H100x1": {"count": 1, "model": "H100 PCIe"},
    "n3-H100x2": {"count": 2, "model": "H100 PCIe"},
    "n3-H100x4": {"count": 4, "model": "H100 PCIe"},
    "n3-H100x8": {"count": 8, "model": "H100 PCIe"},
    "n3-H100x8-NVLink": {"count": 8},
    "n3-H100-SXM5x8": {"count": 8, "model": "H100 80GB HBM3"},
    "n3-A100x8-NVLink": {"count": 8, "model": "A100"},
    # scaleway
    "H100-SXM-8-80G": {"count": 8, "model": "H100 80GB HBM3"},
    "H100-SXM-4-80G": {"count": 4, "model": "H100 80GB HBM3"},
    "H100-SXM-2-80G": {"count": 2, "model": "H100 80GB HBM3"},
    "H100-1-80G": {"count": 1, "model": "H100 PCIe"},
    "L40S-4-48G": {"count": 4, "model": "L40S"},
    "L40S-1-48G": {"count": 1, "model": "L40S"},
    "L4-2-24G": {"count": 2, "model": "NVIDIA L4"},
}


def load_gpu_models(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


# Substring match: "NVIDIA L40" also matches a L40S runner, and no "model" matches anything.
def matches_model(entry, gpu_models):
    if "model" not in entry:
        return True
    return all(entry["model"] in model for model in gpu_models)


def resolve(requested, gpu_info, output_file):
    gpu_names = load_gpu_models(gpu_info)
    gpu_models = sorted(set(gpu_names))
    observed = f"{len(gpu_names)} x {', '.join(gpu_models) or 'no GPU'}"
    print(f"Detected {observed}", flush=True)

    if requested not in HARDWARE:
        print(
            f"Error: hardware '{requested}' is not described in {TABLE_PATH}, the machine this "
            f"benchmark runs on cannot be named. Add an entry for it.",
            file=sys.stderr,
        )
        sys.exit(1)

    by_count = [name for name, entry in HARDWARE.items() if entry["count"] == len(gpu_names)]
    by_model = [name for name in by_count if matches_model(HARDWARE[name], gpu_models)]

    # Several names can match the same GPUs: keep the requested one when it is among them.
    if requested in by_model:
        resolved = requested
    elif len(by_model) == 1:
        resolved = by_model[0]
    elif requested in by_count:
        # Right GPU count but an unexpected model: the table entry is the likely culprit.
        resolved = requested
        print(
            f"Warning: this runner has {observed}, which is not the model recorded for the "
            f"requested {requested} ('{HARDWARE[requested]['model']}') and does not single out "
            f"another hardware either ({', '.join(by_model) or 'no match'}). Keeping "
            f"{requested}, fix its model in {TABLE_PATH}.",
            file=sys.stderr,
        )
    else:
        print(
            f"Error: Slab started a fallback profile, but the machine it gave us cannot be "
            f"named: it has {observed}, which matches {', '.join(by_model) or 'no hardware'} "
            f"while {requested} was requested. Add or fix an entry in {TABLE_PATH}.",
            file=sys.stderr,
        )
        sys.exit(1)

    if resolved != requested:
        print(
            f"Warning: requested {requested} but this runner is a {resolved}: Slab started a "
            f"fallback profile. Results will be sent as {resolved}.",
            file=sys.stderr,
        )

    print(f"Sending results under hardware name: {resolved}", flush=True)
    with open(output_file, "a") as f:
        f.write(f"HARDWARE_NAME={resolved}\n")


parser = argparse.ArgumentParser(
    description="Resolve the hardware name describing the machine a benchmark runs on."
)
parser.add_argument("--requested", required=True, help="hardware name of the requested profile")
parser.add_argument(
    "--gpu-info", required=True, help="file holding one nvidia-smi GPU name per line"
)
parser.add_argument(
    "--output", required=True, help="file to append HARDWARE_NAME to (e.g. $GITHUB_ENV)"
)

if __name__ == "__main__":
    args = parser.parse_args()
    resolve(args.requested, args.gpu_info, args.output)
