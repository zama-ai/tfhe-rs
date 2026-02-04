import collections
import enum
from idlelib import browser

from benchmark_specs import ZKOperation
from formatters.common import ZKGenericFormatter


class Browser(enum.StrEnum):
    Chrome = "chrome"
    Firefox = "firefox"

    @staticmethod
    def from_str(browser_name):
        match browser_name.lower():
            case "chrome":
                return Browser.Chrome
            case "firefox":
                return Browser.Firefox
            case _:
                raise ValueError(f"Browser '{browser_name}' not supported")


DEFAULT_BROWSER = Browser.Chrome


class ZKFormatter(ZKGenericFormatter):
    @staticmethod
    def _get_default_dict() -> collections.defaultdict:
        return collections.defaultdict(
            lambda: {
                ZKOperation.Proof: "N/A",
            }
        )

    @staticmethod
    def _parse_benchmarks_case_variation(case_variation: str):
        parts = case_variation.split("_")
        case = {
            "packed_size": int(parts[0]),
            "crs_size": int(parts[3]),
            "compute_load": parts[8],
            "sub_variation": {},
        }
        try:
            sub_variation_parts = parts[9:]
        except IndexError:
            # No sub variation for this case
            return case

        try:
            browser = Browser.from_str(sub_variation_parts[-1])
            sub_variation_parts.pop()
        except ValueError:
            browser = None

        version = None
        if sub_variation_parts[0].lower().startswith("zkv"):
            version = sub_variation_parts.pop(0)

        details = sub_variation_parts[:]

        case["sub_variation"] = {
            "version": version,
            "browser": browser,
            "details": details,
        }

        return case

    @staticmethod
    def _match_case_variation_filter(case_variation: dict):
        sub_variation = case_variation["sub_variation"]
        try:
            # No details must be specified, otherwise it could mean that a ciphertext
            # size measurement or a non-threaded benchmark case.
            return (
                sub_variation["browser"] == DEFAULT_BROWSER
                and sub_variation["details"] == []
            )
        except KeyError:
            # At least we must have a browser specified.
            return False
