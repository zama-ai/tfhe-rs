from pathlib import Path

try:
    import tomllib  # Python v3.11+
except ModuleNotFoundError:
    import pip._vendor.tomli as tomllib  # the same tomllib that's now included in Python v3.11+


def get_repo_root() -> Path:
    current_file = Path(__file__)
    return current_file.parent.parent.parent


def get_tfhe_version() -> str:
    repo_root = get_repo_root()
    tfhe_cargo_toml_file = "tfhe/Cargo.toml"

    with open(repo_root / tfhe_cargo_toml_file, "rb") as f:
        tfhe_cargo_toml = tomllib.load(f)
        return tfhe_cargo_toml["package"]["version"]


def format_version_major_minor(version: str) -> str:
    hyphenated_version = "v" + version.replace(".", "_")

    if hyphenated_version.count("_") == 1:
        return hyphenated_version
    else:
        return hyphenated_version.rsplit("_", maxsplit=1)[0]
