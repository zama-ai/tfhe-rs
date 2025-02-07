#!/usr/bin/python3

from pathlib import Path

from utils import get_repo_root, format_version_major_minor, get_tfhe_version


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
