import argparse
import concurrent.futures
import csv
import dataclasses
import datetime
import json
import pathlib
import subprocess
import functools

import numpy as np
from scipy.optimize import curve_fit
from sklearn.ensemble import IsolationForest

# Command used to run Rust program responsible to perform sampling on external product.
BASE_COMMAND = 'RUSTFLAGS="-C target-cpu=native" cargo {} {} --release'
# Leave toolchain empty at first
BUILD_COMMAND = BASE_COMMAND.format("{}", "build")
RUN_COMMAND = BASE_COMMAND.format("{}", "run") + " -- --tot {} --id {} {}"

SECS_PER_HOUR = 3600
SECS_PER_MINUTES = 60

parser = argparse.ArgumentParser(description="Compute coefficient correction for external product")
parser.add_argument(
    "--chunks",
    type=int,
    help="Total number of chunks the parameter grid is divided into."
    "Each chunk is run in a sub-process, to speed up processing make sure to"
    " have at least this number of CPU cores to allocate for this task",
)
parser.add_argument(
    "--rust-toolchain",
    type=str,
    help="The rust toolchain to use",
)
parser.add_argument(
    "--output-file",
    "-o",
    type=str,
    dest="output_filename",
    default="correction_coefficients.json",
    help="Output file containing correction coefficients, formatted as JSON"
    " (default: correction_coefficients.json)",
)
parser.add_argument(
    "--analysis-only",
    "-A",
    action="store_true",
    dest="analysis_only",
    help="If this flag is set, no sampling will be done, it will only try to"
    " analyze existing results",
)
parser.add_argument("--dir", type=str, default=".", help="Dir where acquisition files are stored.")
parser.add_argument(
    "--worst-case-analysis",
    "-W",
    dest="worst_case_analysis",
    action="store_true",
    help="Perform a 1000 analysis pruning different outliers, "
    "selecting the wort-case parameter for the fft noise fitting",
)
parser.add_argument(
    "sampling_args",
    nargs=argparse.REMAINDER,
    help="Arguments directly passed to sampling program, to get an exhaustive list"
    " of options run command: `cargo run -- --help`",
)


@dataclasses.dataclass(init=False)
class SamplingLine:
    """
    Extract output variance parameter from a sampling result string.

    :param line: :class:`str` formatted as ``polynomial_size, glwe_dimension,
        decomposition_level_count, decomposition_base_log, input_variance, output_variance,
        predicted_variance``
    """

    parameters: list
    input_variance: float
    output_variance_exp: float
    output_variance_th: float

    def __init__(self, line: dict):
        self.input_variance = float(line["input_variance"])
        self.output_variance_exp = float(line["output_variance"])
        self.output_variance_th = float(line["predicted_variance"])
        self.parameters = [
            float(line["polynomial_size"]),
            float(line["glwe_dimension"]),
            float(line["decomposition_level_count"]),
            float(line["decomposition_base_log"]),
        ]
        # polynomial_size, glwe_dimension, decomposition_level_count, decomposition_base_log
        ggsw_value = int(line["ggsw_encrypted_value"])
        if ggsw_value != 1:
            raise ValueError(f"GGSW value is not 1, it's: {ggsw_value}")


def concatenate_result_files(dir_):
    """
    Concatenate result files into a single one.

    :param pattern: filename pattern as :class:`str`
    :return: concatenated filename as :class:`pathlib.Path`
    """
    results_filepath = pathlib.Path("concatenated_sampling_results")
    files = sorted(pathlib.Path(dir_).glob("*.algo_sample_acquistion"))
    if results_filepath.exists():
        results_filepath.unlink()

    first_file = files[0]
    with results_filepath.open("w", encoding="utf-8") as results:
        content = first_file.read_text()
        (header, sep, _content) = content.partition("\n")
        new_hader = (header + sep).replace(" ", "")
        results.write(new_hader)

    with results_filepath.open("a", encoding="utf-8") as results:
        for file in files:
            content = file.read_text()
            (_header, _sep, content) = content.partition("\n")
            results.write(content.replace(" ", ""))

    return results_filepath


def extract_from_acquisitions(filename):
    """
    Retrieve and parse data from sampling results.

    :param filename: sampling results filename as :class:`pathlib.Path`
    :return: :class:`tuple` of :class:`numpy.array`
    """
    parameters = []
    exp_output_variance = []
    th_output_variance = []
    input_variance = []

    with filename.open() as csvfile:
        csv_reader = csv.DictReader(csvfile, delimiter=",")

        for line in csv_reader:
            try:
                sampled_line = SamplingLine(line)
            except Exception as err:
                # If an exception occurs when parsing a result line, we simply discard this one.
                print(f"Exception while parsing line (error: {err}, line: {line})")
                continue

            exp_output_var = sampled_line.output_variance_exp
            th_output_var = sampled_line.output_variance_th
            input_var = sampled_line.input_variance
            params = sampled_line.parameters

            if exp_output_var < 0.083:
                params.append(th_output_var)
                parameters.append(params)
                exp_output_variance.append(exp_output_var)
                th_output_variance.append(th_output_var)
                input_variance.append(input_var)

    print(f"There is {len(parameters)} samples ...")

    return (
        np.array(parameters),
        np.array(exp_output_variance),
        np.array(th_output_variance),
        np.array(input_variance),
    )


def get_input(filename):
    """
    :param filename: result filename as :class:`pathlib.Path`
    :return: :class:`tuple` of X and Y values
    """
    (
        parameters,
        exp_output_variance,
        _th_output_variance,
        input_variance,
    ) = extract_from_acquisitions(filename)
    y_values = np.maximum(0.0, (exp_output_variance - input_variance))
    x_values = parameters
    return x_values, y_values


def get_input_without_outlier(filename, bits):
    return remove_outlier(bits, *get_input(filename))


def remove_outlier(bits, x_values, y_values):
    """
    Remove outliers from a dataset using an isolation forest algorithm.

    :param x_values: values for the first dimension as :class:`list`
    :param y_values: values for the second dimension as :class:`list`
    :return: cleaned dataset as :class:`tuple` which element storing values a dimension in a
        :class:`list`
    """
    # identify outliers in the training dataset
    iso = IsolationForest(contamination=0.1)  # Contamination value obtained by experience
    yhat = iso.fit_predict(x_values)

    # select all rows that are not outliers
    mask = yhat != -1
    previous_size = len(x_values)
    x_values, y_values = x_values[mask, :], y_values[mask]
    new_size = len(x_values)
    print(f"Removing {previous_size - new_size} outliers ...")
    x_values = x_values.astype(np.float64)
    # Scale the values from variance to modular variance after the filtering was done to avoid
    # overflowing the isolation forest from sklearn
    x_values[:, -1] = x_values[:, -1] * np.float64(2 ** (bits * 2))
    y_values = y_values.astype(np.float64) * np.float64(2 ** (bits * 2))
    return x_values, y_values


def fft_noise(x, a, log2_q):
    """
    Noise formula for FFTW.
    """
    # 53 bits of mantissa kept at most
    bits_lost_per_conversion = max(0, log2_q - 53)
    bit_lost_roundtrip = 2 * bits_lost_per_conversion

    N = x[:, 0]
    k = x[:, 1]
    level = x[:, 2]
    logbase = x[:, 3]
    theoretical_var = x[:, -1]
    return (
        2**a * 2**bit_lost_roundtrip * (k + 1) * level * 2.0 ** (2 * logbase) * N**2
        + theoretical_var
    )


def fft_noise_128(x, a, log2_q):
    """
    Noise formula for f128 fft
    """
    # 106 bits of mantissa kept at most
    bits_lost_per_conversion = max(0, log2_q - 106)
    bit_lost_roundtrip = 2 * bits_lost_per_conversion

    N = x[:, 0]
    k = x[:, 1]
    level = x[:, 2]
    logbase = x[:, 3]
    theoretical_var = x[:, -1]
    # we lose 2 * 11 bits of mantissa per conversion 22 * 2 = 44
    return (
        2**a * 2**bit_lost_roundtrip * (k + 1) * level * 2.0 ** (2 * logbase) * N**2
        + theoretical_var
    )


def log_fft_noise_fun(x, a, fft_noise_fun):
    return np.log2(fft_noise_fun(x, a))


def train(x_values, y_values, fft_noise_fun):
    weights, _ = curve_fit(
        lambda x, a: log_fft_noise_fun(x, a, fft_noise_fun), x_values, np.log2(y_values)
    )
    return weights


def get_weights(filename, fft_noise_fun, bits):
    """
    Get weights from sampling results.

    :param filename: results filename as :class:`pathlib.Path`
    :return: :class:`dict` of weights formatted as ``{"a": <float>}``
    """
    x_values, y_values = get_input_without_outlier(filename, bits)
    weights = train(x_values, y_values, fft_noise_fun)
    test(x_values, y_values, weights, fft_noise_fun)
    return {"a": weights[0]}


def write_to_file(filename, obj):
    """
    Write the given ``obj``ect into a file formatted as JSON.

    :param filename: filename to write into as :class:`str`
    :param obj: object to write as JSON
    """
    filepath = pathlib.Path(filename)
    try:
        with filepath.open("w", encoding="utf-8") as f:
            json.dump(obj, f)
    except Exception as err:
        print(f"Exception occurred while writing to {filename}: {err}")
    else:
        print(f"Results written to {filename}")


def build_sampler(rust_toolchain) -> bool:
    """
    Build sampling Rust program as a subprocess.
    """
    start_time = datetime.datetime.now()
    print("Building sampling program")

    build_command = BUILD_COMMAND.format(rust_toolchain)

    process = subprocess.run(build_command, shell=True, capture_output=True, check=False)

    elapsed_time = (datetime.datetime.now() - start_time).total_seconds()

    stderr = process.stderr.decode()
    stderr_formatted = f"STDERR: {stderr}" if stderr else ""
    print(
        f"Building failed after {elapsed_time} seconds\n"
        f"STDOUT: {process.stdout.decode()}\n"
        f"{stderr_formatted}"
    )

    if process.returncode == 0:
        print(f"Building done in {elapsed_time} seconds")

        return True
    else:
        return False


def run_sampling_chunk(rust_toolchain, total_chunks, identity, input_args) -> bool:
    """
    Run an external product sampling on a chunk of data as a subprocess.

    :param total_chunks: number of chunks the parameter is divided into
    :param identity: chunk identifier as :class:`int`
    :param input_args: arguments passed to sampling program
    """
    cmd = RUN_COMMAND.format(rust_toolchain, total_chunks, identity, input_args)
    start_time = datetime.datetime.now()

    print(f"External product sampling chunk #{identity} starting")

    process = subprocess.run(cmd, shell=True, capture_output=True, check=False)

    elapsed_time = (datetime.datetime.now() - start_time).total_seconds()
    hours = int(elapsed_time // SECS_PER_HOUR)
    minutes = int((elapsed_time % SECS_PER_HOUR) // SECS_PER_MINUTES)
    seconds = int(elapsed_time % SECS_PER_HOUR % SECS_PER_MINUTES)

    if process.returncode == 0:
        print(
            f"External product sampling chunk #{identity} successfully done in"
            f" {hours}:{minutes}:{seconds}"
        )

        return True
    else:
        stderr = process.stderr.decode()
        stderr_formatted = f"STDERR: {stderr}" if stderr else ""
        print(
            f"External product sampling chunk #{identity} failed after"
            f" {hours}:{minutes}:{seconds}\n"
            f"STDOUT: {process.stdout.decode()}\n"
            f"{stderr_formatted}"
        )

        return False


def var_to_bit(variance):
    if variance <= 0:
        return np.nan
    return np.ceil(0.5 * np.log2(variance))


def test(x_values, y_values, weights, fft_noise_fun):
    mse = 0.0
    mse_without_correction = 0.0
    count = 0
    for index in range(len(x_values)):
        params = np.array([x_values[index, :]])
        real_out = y_values[index]
        pred_out = max(fft_noise_fun(params, *list(weights))[0], 0.000001)
        if var_to_bit(real_out) >= var_to_bit(pred_out):
            mse += (var_to_bit(real_out) - var_to_bit(pred_out)) ** 2
            # print(
            #     f"th: {var_to_bit(params[0, -1])}, pred_fft: {var_to_bit(pred_out)}, "
            #     f"real: {var_to_bit(real_out)}"
            # )
            mse_without_correction += (var_to_bit(real_out) - var_to_bit(params[0, -1])) ** 2
            count += 1
        # print(var_to_bit(params[0, -1]))
        # mse_without_correction += (var_to_bit(real_out) ) ** 2

    count = max(count, 1)

    mse /= count  # len(x_values)
    mse_without_correction /= count  # len(x_values)
    print(f"mse: {mse} \nMSE without correction: {mse_without_correction}")
    return mse, mse_without_correction


def main():
    args = parser.parse_args()
    rust_toolchain = args.rust_toolchain
    if rust_toolchain[0] != "+":
        rust_toolchain = f"+{rust_toolchain}"

    sampling_args = list(filter(lambda x: x != "--", args.sampling_args))

    bits = 64
    fft_noise_fun = fft_noise
    if any(arg in ["ext-prod-u128-split", "ext-prod-u128"] for arg in sampling_args):
        fft_noise_fun = fft_noise_128
        bits = 128

    for idx, flag_or_value in enumerate(sampling_args):
        if flag_or_value in ["-q", "--modulus-log2"]:
            bits = int(sampling_args[idx + 1])
            break

    fft_noise_fun = functools.partial(fft_noise_fun, log2_q=bits)

    if not args.analysis_only:
        if not build_sampler(rust_toolchain):
            print("Error while building sampler. Exiting")
            exit(1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.chunks) as executor:
            futures = []
            for n in range(args.chunks):
                futures.append(
                    executor.submit(
                        run_sampling_chunk,
                        rust_toolchain,
                        args.chunks,
                        n,
                        " ".join(sampling_args),
                    )
                )

            # Wait for all sampling chunks to be completed.
            concurrent.futures.wait(futures)

            execution_ok = True

            for future in futures:
                execution_ok = execution_ok and future.result()

            if not execution_ok:
                print("Error while running samplings processes. Check logs.")
                exit(1)

    result_file = concatenate_result_files(args.dir)

    if args.worst_case_analysis:
        max_a = get_weights(result_file, fft_noise_fun, bits)["a"]
        for _ in range(1000):
            weights = get_weights(result_file, fft_noise_fun, bits)
            max_a = max(max_a, weights["a"])
        write_to_file(args.output_filename, {"a": max_a})
    else:
        write_to_file(args.output_filename, get_weights(result_file, fft_noise_fun, bits))


if __name__ == "__main__":
    main()
