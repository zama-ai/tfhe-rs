from pathlib import Path
import re

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

# from https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
def semver_regex(version_str: str):
    return re.match(
        r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
        string=version_str,
        flags=re.M,
    )


def format_version_major_minor(version_str: str) -> str:
    parsed = semver_regex(version_str)
    return f"v{parsed.group('major')}_{parsed.group('minor')}"
