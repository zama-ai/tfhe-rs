#!/usr/bin/env python3
import argparse
import sys


BACKEND_MAP = {
    "aws": "aws",
    "hyperstack": "hyperstack",
    "scaleway": "terraform",
    "nebius": "terraform",
    # Direct terraform prefix: profile name is used as-is (no cloud provider prefix prepended).
    "terraform": "terraform",
}


def parse_profile(profile_string, output_file):
    parts = profile_string.split("::", 1)
    if len(parts) != 2:
        print(
            f"Error: invalid profile format '{profile_string}'.\n"
            f"Expected format: 'backend::profile-name (hardware-name)'",
            file=sys.stderr,
        )
        sys.exit(1)
    backend_prefix, rest = parts

    split_rest = rest.split()
    if len(split_rest) != 2:
        print(
            f"Error: invalid profile format '{rest}'.\n"
            f"Expected format: 'backend::profile-name (hardware-name)'",
            file=sys.stderr,
        )
        sys.exit(1)
    profile_name = split_rest[0]
    hardware_name = split_rest[1].strip("(").strip(")")

    if backend_prefix not in BACKEND_MAP:
        print(
            f"Error: unknown backend '{backend_prefix}'.\n"
            f"Known backends: {', '.join(sorted(BACKEND_MAP.keys()))}",
            file=sys.stderr,
        )
        sys.exit(1)

    slab_backend = BACKEND_MAP[backend_prefix]
    if slab_backend == "terraform" and backend_prefix != "terraform":
        profile = backend_prefix + "-" + profile_name
    else:
        profile = profile_name

    with open(output_file, "a") as f:
        for var_name, value in [
            ("backend", slab_backend),
            ("profile", profile),
            ("hardware", hardware_name),
            ("cloud_provider", backend_prefix)
        ]:
            f.write(f"{var_name}={value}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse a GPU benchmark profile string into backend, profile, and hardware components."
    )
    parser.add_argument(
        "profile_string",
        help='Profile string in the form "backend::profile-name (hardware-name)"',
    )
    parser.add_argument(
        "output_file",
        help="File to append the parsed key=value pairs to (e.g. $GITHUB_OUTPUT)",
    )
    args = parser.parse_args()
    parse_profile(args.profile_string, args.output_file)
