import csv
import json
import math
import pathlib
import sys

from benchmark_specs import Layer

SECONDS_IN_NANO = 1e9
MILLISECONDS_IN_NANO = 1e6
MICROSECONDS_IN_NANO = 1e3

THOUSAND_ELEMENTS = 1e3
MILLION_ELEMENTS = 1e6


def convert_latency_value_to_readable_text(value: int, max_digits: int = 3) -> str:
    """
    Convert timing in nanoseconds to the highest unit usable.

    :param value: timing value
    :type value: int
    :param max_digits: number of digits to keep in the final representation of the value
    :type max_digits: int, optional

    :return: human-readable value with unit
    :rtype: str
    """
    if value > SECONDS_IN_NANO:
        converted_parts = (value / SECONDS_IN_NANO), "s"
    elif value > MILLISECONDS_IN_NANO:
        converted_parts = (value / MILLISECONDS_IN_NANO), "ms"
    elif value > MICROSECONDS_IN_NANO:
        converted_parts = (value / MICROSECONDS_IN_NANO), "us"
    else:
        converted_parts = value, "ns"

    power_of_10 = math.floor(math.log10(converted_parts[0]))
    rounding_digit = max_digits - (power_of_10 + 1)
    if rounding_digit <= 0:
        rounding_digit = None

    if converted_parts[0] >= 100.0:
        rounding_digit = None

    return f"{round(converted_parts[0], rounding_digit)} {converted_parts[1]}"


def convert_throughput_value_to_readable_text(value: int, max_digits: int = 3):
    """
    Convert timing in elements per second to the highest unit usable.

    :param value: timing value
    :type value: int
    :param max_digits: number of digits to keep in the final representation of the value
    :type max_digits: int, optional

    :return: human-readable value with unit
    :rtype:str
    """
    if value > MILLION_ELEMENTS:
        converted_parts = (value / MILLION_ELEMENTS), "M.ops/s"
    elif value > THOUSAND_ELEMENTS:
        converted_parts = (value / THOUSAND_ELEMENTS), "k.ops/s"
    else:
        converted_parts = value, "ops/s"

    if converted_parts[0] > 0:
        power_of_10 = math.floor(math.log10(converted_parts[0]))
        rounding_digit = max_digits - (power_of_10 + 1)
    else:
        rounding_digit = None

    if rounding_digit <= 0:
        rounding_digit = None

    if converted_parts[0] >= 100.0:
        rounding_digit = None

    return f"{round(converted_parts[0], rounding_digit)} {converted_parts[1]}"


def convert_gain_to_text(value: float) -> str:
    """
    Convert gains as :class:`float` to :class:`str`

    :param value: gain value
    :type value: float

    :return: gain as text with percentage sign
    :rtype: str
    """
    return f"{value} %" if value < 0 else f"+{value} %"


def write_to_csv(lines: list, output_filename: str):
    """
    Write data to a CSV file.

    :param lines: formatted data as iterable
    :type lines: list
    :param output_filename: filename where data would be written
    :type output_filename: str
    """
    with pathlib.Path(output_filename).open("w") as csv_file:
        writer = csv.writer(csv_file, delimiter=",")
        for line in lines:
            writer.writerow(line)

    print(f"Results written as CSV in '{output_filename}'")


def write_to_markdown(lines: str | list[str], output_filename: str):
    """
    Write data to a Markdown file.

    :param lines: formatted lines
    :type lines: str | list[str]
    :param output_filename: filename where data would be written
    :type output_filename: str
    """
    if type(lines) != str:
        content = "\n".join(lines) + "\n"
        pathlib.Path(output_filename).write_text(content)
    else:
        pathlib.Path(output_filename).write_text(lines)

    print(f"Results written as Markdown in '{output_filename}'")


def write_to_svg(xml_string: str, output_filename: str):
    """
    Write XML to a SVG file.

    :param xml_string: XML formatted string
    :type xml_string: str
    :param output_filename: filename where data would be written
    :type output_filename: str
    """
    pathlib.Path(output_filename).write_text(xml_string)

    print(f"Results written as SVG in '{output_filename}'")


def write_to_json(data: dict, output_filename: str):
    """
    Write data to a JSON file.

    :param data: data that would be dumped as JSON
    :type data: dict
    :param output_filename: filename where data would be written
    :type output_filename: str
    """
    try:
        dump = json.dumps(data)
    except json.JSONDecodeError as err:
        print(f"couldn't convert results into json format (error: {err})")
        raise

    pathlib.Path(output_filename).write_text(dump)
    print(f"Results written as JSON in '{output_filename}'")


def append_suffix_to_filename(filename: str, suffix: str, stem: str) -> str:
    """
    Appends a suffix to a given filename, considering a specific stem. If the filename
    already ends with the given stem, the suffix is inserted before the stem. Otherwise,
    the suffix and stem are added to the end of the filename.

    :param filename: The original filename to which the suffix and stem will be appended
    :type filename: str
    :param suffix: The string to be appended as the suffix
    :type suffix: str
    :param stem: The specific stem to check or append after the suffix
    :type stem: str

    :return: The new filename with the appended suffix and stem
    :rtype: str
    """
    filename = filename[:]  # Make a copy to avoid modifying the original filename
    if filename.endswith(stem):
        filename = filename[: -len(stem)] + suffix + stem
    else:
        filename += suffix + stem

    return filename
