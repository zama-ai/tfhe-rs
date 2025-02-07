#!/usr/bin/python3

from pathlib import Path

try:
    import tomllib  # Python v3.11+
except ModuleNotFoundError:
    import pip._vendor.tomli as tomllib  # the same tomllib that's now included in Python v3.11+


def get_repo_root():
    current_file = Path(__file__)
    return current_file.parent.parent


def get_tfhe_version():
    repo_root = get_repo_root()
    tfhe_cargo_toml_file = "tfhe/Cargo.toml"

    with open(repo_root / tfhe_cargo_toml_file, "rb") as f:
        tfhe_cargo_toml = tomllib.load(f)
        return tfhe_cargo_toml["package"]["version"]


def format_version_major_minor(version: str):
    hyphenated_version = "v"

    for c in version:
        if c == ".":
            hyphenated_version += "_"
        else:
            hyphenated_version += c

    if hyphenated_version.count("_") == 1:
        return hyphenated_version
    else:
        return hyphenated_version.rsplit("_", maxsplit=1)[0]


def main():
    repo_root = get_repo_root()
    tfhe_current_version = format_version_major_minor(get_tfhe_version())
    shortint_param_file = repo_root / "tfhe/src/shortint/parameters/mod.rs"

    with open(shortint_param_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if "as current_params;" in line:
                print("Content:", line)
                expected = f"use {tfhe_current_version} as current_params;"
                print("Expected use:", expected)
                if not line.endswith(expected):
                    print(
                        "Use clause for current parameters does not match current TFHE-rs version"
                    )
                    exit(1)
                else:
                    print("OK")
                    return
        print("Did not find import line.")
        exit(1)


if __name__ == "__main__":
    main()
