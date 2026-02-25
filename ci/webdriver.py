"""
webdriver
---------

Script to handle tests and benchmarks for client-side tfhe-rs WASM code.
"""

import argparse
import dataclasses
import datetime
import enum
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import threading
import time

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver import Keys
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

parser = argparse.ArgumentParser()
parser.add_argument(
    "-a",
    "--address",
    dest="address",
    default="localhost",
    help="Address to testing Node server",
)
parser.add_argument(
    "-p",
    "--port",
    dest="port",
    default=3000,
    type=int,
    help="Port to testing Node server",
)
parser.add_argument(
    "-k",
    "--browser-kind",
    dest="browser_kind",
    choices=["chrome", "firefox"],
    required=True,
    help="Path to web driver file",
)
parser.add_argument(
    "-b",
    "--browser-path",
    dest="browser_path",
    required=True,
    help="Path to browser file",
)
parser.add_argument(
    "-d",
    "--driver-path",
    dest="driver_path",
    required=True,
    help="Path to web driver file",
)
parser.add_argument(
    "--index-path",
    dest="index_path",
    default="tfhe/web_wasm_parallel_tests/index.html",
    help="Path to HTML index file containing all the tests/benchmarks",
)
parser.add_argument(
    "--id-pattern",
    dest="id_filter_pattern",
    help="Pattern to use to filter HTML button ID displayed on web page",
)
parser.add_argument(
    "--value-pattern",
    dest="value_filter_pattern",
    help="Pattern to use to filter HTML button value displayed on web page",
)
parser.add_argument(
    "-f",
    "--fail-fast",
    dest="fail_fast",
    action="store_true",
    help="Exit on first failed test",
)
parser.add_argument(
    "--server-cmd",
    dest="server_cmd",
    help="Command to execute to launch web server in the background",
)
parser.add_argument(
    "--server-workdir",
    dest="server_workdir",
    help="Path to working directory to launch web server",
)


class BrowserKind(enum.Enum):
    """
    Kind of browsers currently supported
    """

    chrome = 1
    firefox = 2


class Driver:
    """
    Representation of a web driver relying on Selenium.
    """

    def __init__(self, browser_path, driver_path, browser_kind, threaded_logs=False):
        """
        :param browser_path: path to binary web browser as :class:`str`
        :param driver_path: path to binary web driver as :class:`str`
        :param browser_kind: :class:`BrowserKind`
        :param threaded_logs: launch a thread to display log in parallel
        """
        self.browser_path = browser_path
        self.driver_path = driver_path

        self._is_threaded_logs = threaded_logs
        self._log_thread = None

        self.browser_kind = browser_kind

        match self.browser_kind:
            case BrowserKind.chrome:
                self.options = ChromeOptions()
                if os.getuid() == 0:
                    # If user ID is root then driver needs to run in no-sandbox mode.
                    print(
                        "Script is running as root, running browser with --no-sandbox for compatibility"
                    )
                self.options.add_argument("--no-sandbox")
            case BrowserKind.firefox:
                self.options = FirefoxOptions()

        self.options.binary_location = self.browser_path
        # Needed for wasm-par-mq sync executor mode
        self.options.add_argument("--headless=new")
        self.options.add_argument("--enable-features=ServiceWorker")

        self._driver = None

        self.shutting_down = False

    def get_driver(self):
        if self._driver is None:

            match self.browser_kind:
                case BrowserKind.chrome:
                    driver_service = ChromeService(self.driver_path)
                    self.options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
                    self._driver = webdriver.Chrome(
                        service=driver_service, options=self.options
                    )
                    if self._is_threaded_logs:
                        self._log_thread = threading.Thread(target=self._threaded_logs)
                case BrowserKind.firefox:
                    driver_service = FirefoxService(self.driver_path)
                    self.options.log.level = "trace"
                    self.options.enable_bidi = True
                    self._driver = webdriver.Firefox(
                        service=driver_service, options=self.options
                    )
                    self._driver.script.add_console_message_handler(
                        self._on_console_logs
                    )
                case _:
                    print(
                        f"{self.browser_kind.name.capitalize()} browser driver is not supported"
                    )
                    sys.exit(1)

            if self._log_thread:
                self._log_thread.start()

        return self._driver

    def get_page(self, server_url, timeout_seconds=10):
        dr = self.get_driver()
        dr.get(server_url)
        self.wait_for_page_load(self.get_waiter(timeout_seconds))

    def get_waiter(self, timeout):
        return WebDriverWait(self.get_driver(), timeout)

    def wait_for_page_load(self, waiter):
        waiter.until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )

    def wait_for_button(self, waiter, element_id):
        return waiter.until(EC.element_to_be_clickable((By.ID, element_id)))

    def wait_for_selection(self, waiter, element):
        return waiter.until(EC.element_to_be_selected(element))

    def find_element(self, element_id):
        return self.get_driver().find_element(By.ID, element_id)

    def _on_console_logs(self, log):
        """
        Callback used for retrieving console log using BiDi protocol reling on websocket
        """
        # Filter out useless message
        if "using deprecated parameters" in log.text:
            return

        print(f"{log.level.upper()}: {log.text}")

    def print_log(self, log_type):
        logs = self.get_driver().get_log(log_type)
        for log in logs:
            # Filter out useless message
            if "using deprecated parameters" in log["message"]:
                continue

            # String pattern is `<server url> <line:col> "<log message>"`
            # We only care for <log message> part.
            content = log["message"].split(maxsplit=2)[-1].strip('"')
            print(f"{log['level']}: {content}")

    def _threaded_logs(self):
        while not self.shutting_down:
            self.print_log("browser")
            time.sleep(0.2)

    def refresh(self):
        match self.browser_kind:
            case BrowserKind.chrome:
                self.get_driver().refresh()
            case BrowserKind.firefox:
                # Need to force refresh in Firefox to avoid script caching by web workers
                self.get_driver().find_element(By.TAG_NAME, "body").send_keys(
                    Keys.CONTROL + Keys.SHIFT + "R"
                )

    def quit(self):
        self.shutting_down = True
        if self._log_thread:
            self._log_thread.join()

        if self._driver:
            self.get_driver().quit()


@dataclasses.dataclass
class UseCase:
    """
    Use case extracted from an HTML element.
    """

    id: str
    value: str
    timeout_seconds: int


class Cases:
    """
    Container for :class:`UseCase`.
    """

    def __init__(self):
        self._cases = []

    def __iter__(self):
        return self._cases.__iter__()

    def append(self, use_case):
        self._cases.append(use_case)

    def _filter(self, field, pattern):
        return [case for case in self._cases if pattern in getattr(case, field)]

    def filter_by_id(self, pattern):
        """
        Filter use cases by their HTML `id` attribute.

        :param pattern: :class:`str` that would be included in `id`

        :return: :class:`list` comprehension of :class:`UseCase`
        """
        return self._filter("id", pattern)

    def filter_by_value(self, pattern):
        """
        Filter use cases by their HTML `value` attribute.

        :param pattern: :class:`str` that would be included in `value`

        :return: :class:`list` comprehension of :class:`UseCase`
        """
        return self._filter("value", pattern)


def parse_html_index(filepath):
    """
    Parse HTML index containing all the element that can be handled by a webdriver.
    Each supported element will be turned into a :class:`UseCase` which will be
    appended to a container of :class:`Cases`.

    :param filepath: path to index file as :class:`pathlib.Path`

    :return: :class:`Cases`
    """
    cases = Cases()

    soup = BeautifulSoup(filepath.read_text(), "html.parser")
    for tag in soup.find_all("input"):
        if tag["type"] != "button":
            continue

        case_timeout_seconds = int(tag.get("max", "60"))
        cases.append(UseCase(tag["id"], tag["value"], case_timeout_seconds))

    return cases


def run_case(driver, case):
    """
    Run test or benchmark case using a web driver.
    If case is too long to run, it will raise an :exec:`TimeoutException`.

    :param driver: :class:`Driver`
    :param case: :class:`UseCase`

    :return: :class:`dict` of benchmark results if `case` is benchmarks otherwise `None`
    """
    page_waiter = driver.get_waiter(10)
    test_waiter = driver.get_waiter(case.timeout_seconds)

    print("[driver] Wait for page to load")
    driver.wait_for_page_load(page_waiter)

    print(f"[driver] Wait for HTML button to be clickable (id: {case.id})")
    button = driver.wait_for_button(page_waiter, case.id)
    button.click()

    checkbox_id = "testSuccess"
    checkbox = driver.find_element(checkbox_id)
    try:
        print("[driver] Wait for result checkbox to be checked")
        driver.wait_for_selection(test_waiter, checkbox)
    except TimeoutException:
        driver.refresh()
        raise TimeoutException(
            f"timed out after {case.timeout_seconds} seconds waiting for result checkbox to be checked"
        )

    benchmark_results = driver.find_element("benchmarkResults").get_attribute("value")

    driver.refresh()

    return json.loads(benchmark_results) if benchmark_results else None


def dump_benchmark_results(results, browser_kind):
    """
    Dump as JSON benchmark results into a file.
    If `results` is an empty dict then this function is a no-op.
    If the file already exists, new results are merged with existing ones,
    overwriting keys that already exist.

    :param results: benchmark results as :class:`dict`
    :param browser_kind: browser as :class:`BrowserKind`
    """
    if results:
        results = {
            key.replace("mean", "_".join((browser_kind.name, "mean"))): val
            for key, val in results.items()
        }
        results_path = pathlib.Path("tfhe-benchmark/wasm_benchmark_results.json")
        existing_results = {}
        if results_path.exists():
            try:
                existing_results = json.loads(results_path.read_text())
            except json.JSONDecodeError:
                pass
        existing_results.update(results)
        results_path.write_text(json.dumps(existing_results))


def start_web_server(
    command, working_directory, server_address, server_port, startup_timeout_seconds=30
):
    """
    Start web server with custom command as a subprocess.

    :param command: command to start the server as :class:`str`
    :param working_directory: path to directory to move before running `command`
    :param server_address: web server address
    :param server_port: web server port as :class:`int`
    :param startup_timeout_seconds: duration in seconds to let server start up

    :return: :class:`subprocess.Popen`
    """
    try:
        sock = socket.create_connection((server_address, server_port), timeout=2)
    except (TimeoutError, ConnectionRefusedError):
        # Nothing is alive at this URL, ignoring exception
        pass
    else:
        sock.close()
        raise ConnectionError(
            f"address and port already in use at ({server_address}, {server_port})"
        )

    proc = subprocess.Popen(
        command.split(),
        cwd=working_directory,
        stdout=subprocess.DEVNULL,
        start_new_session=True,
    )

    print("Starting web server")

    timeout_seconds = 0.5
    start_date = datetime.datetime.now()
    while (
        datetime.datetime.now() - start_date
    ).total_seconds() < startup_timeout_seconds:
        try:
            sock = socket.create_connection(
                (server_address, server_port), timeout=timeout_seconds
            )
        except TimeoutError:
            pass
        except ConnectionRefusedError:
            time.sleep(timeout_seconds)
        else:
            sock.close()
            break
    else:
        terminate_web_server(proc.pid)
        raise TimeoutError(
            f"timeout after {startup_timeout_seconds} seconds while waiting for web server"
        )

    return proc


def terminate_web_server(pid):
    """
    Terminate web server process.

    :param pid: process ID as :class:`int`
    """
    # Killing process group since the server is a child process of
    # spawned subprocess. Using a simple kill() would let the server
    # alive even after exiting this program.
    os.killpg(os.getpgid(pid), signal.SIGTERM)


def main():
    args = parser.parse_args()
    browser_kind = BrowserKind[args.browser_kind]

    exit_code = 0

    cases = parse_html_index(pathlib.Path(args.index_path))
    if args.id_filter_pattern:
        cases = cases.filter_by_id(args.id_filter_pattern)
    elif args.value_filter_pattern:
        cases = cases.filter_by_value(args.value_filter_pattern)

    server_process = None
    if args.server_cmd:
        try:
            server_process = start_web_server(
                args.server_cmd, args.server_workdir, args.address, args.port
            )
        except Exception as err:
            print(f"Failed to start web server (error: {err})")
            sys.exit(1)

    print("Starting web driver")
    driver = Driver(
        args.browser_path, args.driver_path, browser_kind, threaded_logs=True
    )

    driver.get_page(f"http://{args.address}:{args.port}", timeout_seconds=10)

    failures = []
    benchmark_results = {}

    for case in cases:
        try:
            bench_res = run_case(driver, case)
            print(f"SUCCESS: {case.id}\n")
            if bench_res:
                benchmark_results.update(bench_res)
        except KeyboardInterrupt:
            exit_code = 2
            break
        except Exception as error:
            print(f"FAIL: {case.id} (reason: {error})\n")
            if args.fail_fast:
                print("Fail fast is enabled, exiting")
                exit_code = 1
                break
            else:
                failures.append(case.id)

    dump_benchmark_results(benchmark_results, browser_kind)

    # Close the browser
    driver.quit()

    if server_process:
        print("Shutting down web server")
        terminate_web_server(server_process.pid)

    if failures:
        exit_code = 1
        print("Following tests have failed:")
        for case_name in failures:
            print(f"* {case_name}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
