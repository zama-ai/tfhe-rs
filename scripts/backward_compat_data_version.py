#!/usr/bin/python3

try:
    import tomllib  # Python v3.11+
except ModuleNotFoundError:
    import pip._vendor.tomli as tomllib  # the same tomllib that's now included in Python v3.11+


fname = "tests/Cargo.toml"
with open(fname, "rb") as f:
    data = tomllib.load(f)

    dev_dependencies = data["dev-dependencies"]

    branch_name = dev_dependencies["tfhe-backward-compat-data"]["branch"]

    print(branch_name)
