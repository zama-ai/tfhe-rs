"""
hardware_finder
---------------

This script parses ci/slab.toml file to find the hardware name associated with a given pair of backend and a profile name.
"""

import argparse
import enum
import pathlib
import sys
import tomllib
from typing import Any

parser = argparse.ArgumentParser()
parser.add_argument(
    "backend",
    choices=["aws", "hyperstack"],
    help="Backend instance provider",
)
parser.add_argument(
    "profile",
    help="Instance profile name",
)

SLAB_FILE = pathlib.Path("ci/slab.toml")


class Backend(enum.StrEnum):
    Aws = "aws"
    Hyperstack = "hyperstack"
    Hpu = "hpu"  # Only v80 is supported for now

    @staticmethod
    def from_str(label):
        match label.lower():
            case "aws":
                return Backend.Aws
            case "hyperstack":
                return Backend.Hyperstack
            case _:
                raise NotImplementedError


def parse_toml_file(path):
    """
    Parse TOML file.

    :param path: path to TOML file
    :return: file content as :class:`dict`
    """
    try:
        return tomllib.loads(pathlib.Path(path).read_text())
    except tomllib.TOMLDecodeError as err:
        raise RuntimeError(f"failed to parse definition file (error: {err})")


def find_hardware_name(config_file: dict[str, Any], backend: Backend, profile: str):
    """
    Find hardware name associated with :class:`Backend` and :class:`str` profile name.

    :param config_file: parsed slab.toml file
    :param backend: backend name
    :param profile: profile name

    :return: hardware name as :class:`str`
    """
    try:
        definition = config_file["backend"][backend.value][profile]
    except KeyError:
        section_name = f"backend.{backend.value}.{profile}"
        raise KeyError(f"no definition found for `[{section_name}]` in {SLAB_FILE}")

    match backend:
        case Backend.Aws:
            return definition["instance_type"]
        case Backend.Hyperstack:
            return definition["flavor_name"]
        case _:
            raise NotImplementedError


if __name__ == "__main__":
    args = parser.parse_args()

    parsed_toml = parse_toml_file(SLAB_FILE)
    backend = Backend.from_str(args.backend)
    try:
        hardware_name = find_hardware_name(parsed_toml, backend, args.profile)
    except Exception as err:
        print(
            f"failed to find hardware name for ({args.backend}, {args.profile}): {err}"
        )
        sys.exit(1)
    else:
        print(hardware_name)
