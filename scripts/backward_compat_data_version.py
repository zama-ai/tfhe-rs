#!/usr/bin/python3

import tomllib

fname = "tests/Cargo.toml"
with open(fname, "rb") as f:
    data = tomllib.load(f)

    dev_dependencies = data.get("dev-dependencies")

    branch_name = dev_dependencies["tfhe-backward-compat-data"].get("branch")

    print(branch_name)
