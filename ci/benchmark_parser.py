"""
benchmark_parser
----------------

Parse criterion benchmark results.
"""
import argparse
import pathlib
import json
import sys


parser = argparse.ArgumentParser()
parser.add_argument('results_dir',
                    help='Location of criterion benchmark results directory')
parser.add_argument('output_file', help='File storing parsed results')
parser.add_argument('-d', '--database', dest='database',
                    help='Name of the database used to store results')
parser.add_argument('-w', '--hardware', dest='hardware',
                    help='Hardware reference used to perform benchmark')
parser.add_argument('-V', '--project-version', dest='project_version',
                    help='Commit hash reference')
parser.add_argument('-b', '--branch', dest='branch',
                    help='Git branch name on which benchmark was performed')
parser.add_argument('--commit-date', dest='commit_date',
                    help='Timestamp of commit hash used in project_version')
parser.add_argument('--bench-date', dest='bench_date',
                    help='Timestamp when benchmark was run')
parser.add_argument('--name-suffix', dest='name_suffix', default='',
                    help='Suffix to append to each of the result test names')
parser.add_argument('--append-results', dest='append_results', action='store_true',
                    help='Append parsed results to an existing file')


def recursive_parse(directory, name_suffix=""):
    """
    Parse all the benchmark results in a directory. It will attempt to parse all the files having a
    .json extension at the top-level of this directory.

    :param directory: path to directory that contains raw results as :class:`pathlib.Path`
    :param name_suffix: a :class:`str` suffix to apply to each test name found

    :return: :class:`list` of data points
    """
    excluded_directories = ["child_generate", "fork", "parent_generate", "report"]
    result_values = list()
    for dire in directory.iterdir():
        if dire.name in excluded_directories or not dire.is_dir():
            continue
        for subdir in dire.iterdir():
            if subdir.name != "new":
                continue

            test_name = parse_benchmark_file(subdir)
            for stat_name, value in parse_estimate_file(subdir).items():
                test_name_parts = list(filter(None, [test_name, stat_name, name_suffix]))
                result_values.append({"value": value, "test": "_".join(test_name_parts)})

    return result_values


def parse_benchmark_file(directory):
    """
    Parse file containing details of the parameters used for a benchmark.

    :param directory: directory where a benchmark case results are located as :class:`pathlib.Path`

    :return: name of the test as :class:`str`
    """
    raw_results = _parse_file_to_json(directory, "benchmark.json")
    return raw_results["full_id"].replace(" ", "_")


def parse_estimate_file(directory):
    """
    Parse file containing timing results for a benchmark.

    :param directory: directory where a benchmark case results are located as :class:`pathlib.Path`

    :return: :class:`dict` of data points
    """
    raw_results = _parse_file_to_json(directory, "estimates.json")
    return {
        stat_name: raw_results[stat_name]["point_estimate"]
        for stat_name in ("mean", "std_dev")
    }


def _parse_file_to_json(directory, filename):
    result_file = directory.joinpath(filename)
    return json.loads(result_file.read_text())


def dump_results(parsed_results, filename, input_args):
    """
    Dump parsed results formatted as JSON to file.

    :param parsed_results: :class:`list` of data points
    :param filename: filename for dump file as :class:`pathlib.Path`
    :param input_args: CLI input arguments
    """
    if input_args.append_results:
        parsed_content = json.loads(filename.read_text())
        parsed_content["points"].extend(parsed_results)
        filename.write_text(json.dumps(parsed_content))
    else:
        filename.parent.mkdir(parents=True, exist_ok=True)
        series = {
            "database": input_args.database,
            "hardware": input_args.hardware,
            "project_version": input_args.project_version,
            "branch": input_args.branch,
            "insert_date": input_args.bench_date,
            "commit_date": input_args.commit_date,
            "points": parsed_results,
        }
        filename.write_text(json.dumps(series))


def check_mandatory_args(input_args):
    """
    Check for availability of required input arguments, the program will exit if one of them is
    not present. If `append_results` flag is set, all the required arguments will be ignored.

    :param input_args: CLI input arguments
    """
    if input_args.append_results:
        return

    missing_args = list()
    for arg_name in vars(input_args):
        if arg_name in ["results_dir", "output_file", "name_suffix", "append_results"]:
            continue
        if not getattr(input_args, arg_name):
            missing_args.append(arg_name)

    if missing_args:
        for arg_name in missing_args:
            print(f"Missing required argument: --{arg_name.replace('_', '-')}")
        sys.exit(1)


if __name__ == "__main__":
    args = parser.parse_args()
    check_mandatory_args(args)

    print("Parsing benchmark results... ")
    results = recursive_parse(pathlib.Path(args.results_dir), args.name_suffix)
    print("Parsing results done")

    output_file = pathlib.Path(args.output_file)
    print(f"Dump parsed results into '{output_file.resolve()}' ... ", end="")
    dump_results(results, output_file, args)

    print("Done")
