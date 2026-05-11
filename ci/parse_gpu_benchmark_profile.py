#!/usr/bin/env python3
import argparse
import sys
import tomllib


BACKEND_MAP = {
    "aws": "aws",
    "hyperstack": "hyperstack",
    "scaleway": "terraform",
}


def parse_profile(profile_string, output_file, slab_toml):
    backend_prefix, rest = profile_string.split("::", 1)

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
    if slab_backend == "terraform":
        profile = backend_prefix + "-" + profile_name
    else:
        profile = profile_name

    with open(slab_toml, "rb") as f:
        slab = tomllib.load(f)

    available = slab.get("backend", {}).get(slab_backend, {})
    if profile not in available:
        print(
            f"Error: profile '{profile}' not found under [backend.{slab_backend}] in {slab_toml}.\n"
            f"Known profiles: {', '.join(sorted(available.keys()))}",
            file=sys.stderr,
        )
        sys.exit(1)

    entry = available[profile]
    expected_hardware = entry.get("flavor_name") or entry.get("instance_type")
    assert expected_hardware is not None, (
        f"profile '{profile}' in {slab_toml} has neither 'flavor_name' nor 'instance_type'"
    )
    if hardware_name != expected_hardware:
        print(
            f"Error: hardware '{hardware_name}' does not match expected '{expected_hardware}' "
            f"for profile '{profile}' in {slab_toml}.",
            file=sys.stderr,
        )
        sys.exit(1)

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
    parser.add_argument(
        "--slab-toml",
        default="ci/slab.toml",
        help="Path to slab.toml (default: ci/slab.toml)",
    )
    args = parser.parse_args()
    parse_profile(args.profile_string, args.output_file, args.slab_toml)
