import tempfile
import unittest
import unittest.mock as mock

import connector
import benchmark_specs
import utils


class TestBenchmarksSpecsEnumMixin:
    callable_func = None
    cases = []
    valid_str_case_insensitive = ()

    def test_valid_variant_from_str(self):
        if not self.cases:
            self.fail("No cases to test")

        for user_str, expected_variant in self.cases:
            with self.subTest(user_str=user_str):
                self.assertEqual(type(self).callable_func(user_str), expected_variant)

    def test_invalid_variant_from_str(self):
        with self.assertRaises(NotImplementedError):
            type(self).callable_func("invalid_backend")

    def test_user_str_case_insensitive(self):
        user_str = self.valid_str_case_insensitive[0]
        expected = self.valid_str_case_insensitive[1]
        self.assertEqual(type(self).callable_func(user_str), expected)


class SpecsBackendTest(TestBenchmarksSpecsEnumMixin, unittest.TestCase):
    callable_func = benchmark_specs.Backend.from_str
    cases = [
        ("cpu", benchmark_specs.Backend.CPU),
        ("gpu", benchmark_specs.Backend.GPU),
        ("hpu", benchmark_specs.Backend.HPU),
    ]
    valid_str_case_insensitive = ("CpU", benchmark_specs.Backend.CPU)


class SpecsLayerTest(TestBenchmarksSpecsEnumMixin, unittest.TestCase):
    callable_func = benchmark_specs.Layer.from_str
    cases = [
        ("hlapi", benchmark_specs.Layer.HLApi),
        ("integer", benchmark_specs.Layer.Integer),
        ("shortint", benchmark_specs.Layer.Shortint),
        ("core_crypto", benchmark_specs.Layer.CoreCrypto),
    ]
    valid_str_case_insensitive = ("IntEgER", benchmark_specs.Layer.Integer)


class SpecsCoreCryptoOperationsTest(TestBenchmarksSpecsEnumMixin, unittest.TestCase):
    callable_func = benchmark_specs.CoreCryptoOperation.from_str
    cases = [
        ("keyswitch", benchmark_specs.CoreCryptoOperation.KeySwitch),
        ("pbs_mem_optimized", benchmark_specs.CoreCryptoOperation.PBS),
        ("multi_bit_pbs", benchmark_specs.CoreCryptoOperation.MultiBitPBS),
        (
            "multi_bit_deterministic_pbs",
            benchmark_specs.CoreCryptoOperation.MultiBitPBS,
        ),
        ("ks_pbs", benchmark_specs.CoreCryptoOperation.KeySwitchPBS),
        ("multi_bit_ks_pbs", benchmark_specs.CoreCryptoOperation.KeySwitchMultiBitPBS),
        (
            "multi_bit_deterministic_ks_pbs",
            benchmark_specs.CoreCryptoOperation.KeySwitchMultiBitPBS,
        ),
    ]
    valid_str_case_insensitive = (
        "kEysWitCH",
        benchmark_specs.CoreCryptoOperation.KeySwitch,
    )


class SpecsPBSKindTest(TestBenchmarksSpecsEnumMixin, unittest.TestCase):
    callable_func = benchmark_specs.PBSKind.from_str
    cases = [
        ("classical", benchmark_specs.PBSKind.Classical),
        ("multi_bit", benchmark_specs.PBSKind.MultiBit),
        ("any", benchmark_specs.PBSKind.Any),
    ]
    valid_str_case_insensitive = ("ClaSSical", benchmark_specs.PBSKind.Classical)


class SpecsNoiseDistributionTest(TestBenchmarksSpecsEnumMixin, unittest.TestCase):
    callable_func = benchmark_specs.NoiseDistribution.from_str
    cases = [
        ("gaussian", benchmark_specs.NoiseDistribution.Gaussian),
        ("tuniform", benchmark_specs.NoiseDistribution.TUniform),
    ]
    valid_str_case_insensitive = (
        "gAuSsian",
        benchmark_specs.NoiseDistribution.Gaussian,
    )


class SpecsBenchTypeTest(TestBenchmarksSpecsEnumMixin, unittest.TestCase):
    callable_func = benchmark_specs.BenchType.from_str
    cases = [
        ("latency", benchmark_specs.BenchType.Latency),
        ("throughput", benchmark_specs.BenchType.Throughput),
    ]
    valid_str_case_insensitive = ("lAtEncy", benchmark_specs.BenchType.Latency)


class SpecsErrorFailureProbabilityTest(unittest.TestCase):
    def test_valid_values_from_params(self):
        cases = [
            ("PARAM_NAME_2M40", benchmark_specs.ErrorFailureProbability.TWO_MINUS_40),
            ("PARAM_NAME_2M64", benchmark_specs.ErrorFailureProbability.TWO_MINUS_64),
            ("PARAM_NAME_2M128", benchmark_specs.ErrorFailureProbability.TWO_MINUS_128),
        ]

        for param, expected_variant in cases:
            with self.subTest(param_name=param):
                self.assertEqual(
                    benchmark_specs.ErrorFailureProbability.from_param_name(param),
                    expected_variant,
                )

    def test_pfail_value_not_supported(self):
        with self.assertRaises(NotImplementedError):
            benchmark_specs.ErrorFailureProbability.from_param_name("PARAM_NAME_2M256")

    def test_pfail_not_in_param_name(self):
        with self.assertRaises(ValueError):
            benchmark_specs.ErrorFailureProbability.from_param_name("PARAM_NAME")

    def test_bad_pfail(self):
        with self.assertRaises(ValueError):
            benchmark_specs.ErrorFailureProbability.from_param_name(
                "PARAM_NAME_2MnotAnInteger"
            )


class SpecsBenchDetailsTest(unittest.TestCase):
    def test_parse_integer_test_name(self):
        layer = benchmark_specs.Layer.Integer

        cases = [
            ("add", "add", benchmark_specs.SignFlavor.Unsigned),
            ("signed::add", "add", benchmark_specs.SignFlavor.Signed),
            ("cuda::add", "add", benchmark_specs.SignFlavor.Unsigned),
            ("cuda::unsigned::add", "add", benchmark_specs.SignFlavor.Unsigned),
            ("cuda::signed::add", "add", benchmark_specs.SignFlavor.Signed),
            ("hpu::add", "add", benchmark_specs.SignFlavor.Unsigned),
        ]
        for test, expected_op_name, expected_sign_flavor in cases:
            with self.subTest(test=test):
                details = benchmark_specs.BenchDetails(
                    layer, f"integer::{test}::ANY_PARAM_NAME::64_bits", 64
                )
                self.assertEqual(details.operation_name, expected_op_name)
                self.assertEqual(details.sign_flavor, expected_sign_flavor)

    def test_parse_core_crypto_test_name(self):
        layer = benchmark_specs.Layer.CoreCrypto
        # CPU backend
        details = benchmark_specs.BenchDetails(
            layer, "core_crypto::pbs::ANY_PARAMS_NAME", 64
        )
        self.assertEqual(details.operation_name, "pbs")
        # GPU backend
        details = benchmark_specs.BenchDetails(
            layer, "core_crypto::cuda::pbs::ANY_PARAMS_NAME", 64
        )
        self.assertEqual(details.operation_name, "pbs")

    def test_parse_hlapi_test_name(self):
        layer = benchmark_specs.Layer.HLApi

        cases = [
            ("ops::add", "ops::add"),
            ("cuda::ops::add", "ops::add"),
            ("hpu::ops::add", "ops::add"),
        ]
        for test, expected_op_name in cases:
            with self.subTest(test=test):
                details = benchmark_specs.BenchDetails(
                    layer, f"hlapi::{test}::ANY_PARAM_NAME::FheUint64", 64
                )
                self.assertEqual(details.operation_name, expected_op_name)
                # TODO Convert rust_type which is a string to RustType variant in the implementation.
                # self.assertEqual(details.rust_type, benchmark_specs.RustType.FheUint64)

        cases = [
            ("erc20::transfer", "erc20::transfer"),
            ("cuda::dex::swap_claim", "dex::swap_claim"),
            ("hpu::erc20::transfer::whitepaper", "erc20::transfer::whitepaper"),
        ]
        for test, expected_op_name in cases:
            with self.subTest(test=test):
                details = benchmark_specs.BenchDetails(
                    layer, f"hlapi::{test}::FheUint64", 64
                )
                self.assertEqual(details.operation_name, expected_op_name)

    def test_parse_shortint_test_name(self):
        details = benchmark_specs.BenchDetails(
            benchmark_specs.Layer.Shortint,
            "shortint::add::ANY_PARAM_NAME::FheUint64",
            64,
        )
        self.assertEqual(details.operation_name, "add")


class UtilsTest(unittest.TestCase):
    def test_latency_value_to_text_conversion(self):
        cases = [
            (1.2e10, "12.0 s"),
            (345e6, "345 ms"),
            (5e3, "5.0 us"),
            (789, "789 ns"),
        ]

        for value, expected_str in cases:
            with self.subTest(value=value):
                self.assertEqual(
                    utils.convert_latency_value_to_readable_text(value), expected_str
                )

    def test_latency_value_to_text_conversion_with_limited_digits(self):
        cases = [
            (100.0e9, "100 s", 3),  # Numbers above 100.0 doesn't display digits
            (100.8e9, "101 s", 4),  # Numbers above 100.0 are still rounded
            (4.678e6, "5 ms", 0),
            (4.678e6, "5 ms", 1),
            (4.678e6, "4.7 ms", 2),
            (4.678e6, "4.68 ms", 3),
            (4.678e6, "4.678 ms", 4),
        ]

        for value, expected_str, max_digits in cases:
            with self.subTest(value=value, max_digits=max_digits):
                self.assertEqual(
                    utils.convert_latency_value_to_readable_text(value, max_digits),
                    expected_str,
                )

    def test_throughput_value_to_text_conversion(self):
        cases = [
            (123, "123 ops/s"),
            (123456, "123 k.ops/s"),
            (1234567, "1.23 M.ops/s"),
        ]

        for value, expected_str in cases:
            with self.subTest(value=value):
                self.assertEqual(
                    utils.convert_throughput_value_to_readable_text(value), expected_str
                )

    def test_throughput_value_to_text_conversion_with_limited_digits(self):
        cases = [
            (100.0, "100 ops/s", 3),  # Numbers above 100.0 doesn't display digits
            (100.8, "101 ops/s", 4),  # Numbers above 100.0 are still rounded
            (4.678, "5 ops/s", 0),
            (4.678, "5 ops/s", 1),
            (4.678, "4.7 ops/s", 2),
            (4.678, "4.68 ops/s", 3),
            (4.678, "4.678 ops/s", 4),
        ]

        for value, expected_str, max_digits in cases:
            with self.subTest(value=value, max_digits=max_digits):
                self.assertEqual(
                    utils.convert_throughput_value_to_readable_text(value, max_digits),
                    expected_str,
                )

    def test_convert_gain_to_text(self):
        cases = [
            (0.0, "+0.0 %"),
            (0, "+0 %"),
            (1, "+1 %"),
            (1.2, "+1.2 %"),
            (-1.3, "-1.3 %"),
        ]

        for gain, expected_str in cases:
            with self.subTest(gain=gain):
                self.assertEqual(utils.convert_gain_to_text(gain), expected_str)


class PostgreConfigTest(unittest.TestCase):
    def get_working_config(self):
        conf_file = tempfile.NamedTemporaryFile()
        conf_file.write(
            b"""
        [postgre]
        host = config_host
        user = config_user
        password = config_password
        """
        )
        conf_file.flush()

        return conf_file

    @mock.patch.dict("os.environ", {}, clear=True)
    def test_empty_config(self):
        config = connector.PostgreConfig()
        self.assertIsNone(config.host)
        self.assertIsNone(config.user)
        self.assertIsNone(config.password)

    @mock.patch.dict(
        "os.environ",
        {
            "DATA_EXTRACTOR_DATABASE_HOST": "env_host",
            "DATA_EXTRACTOR_DATABASE_USER": "env_user",
            "DATA_EXTRACTOR_DATABASE_PASSWORD": "env_password",
        },
    )
    def test_config_use_env(self):
        config = connector.PostgreConfig()
        self.assertEqual(config.host, "env_host")
        self.assertEqual(config.user, "env_user")
        self.assertEqual(config.password, "env_password")

    @mock.patch.dict("os.environ", {}, clear=True)
    def test_config_from_file(
        self,
    ):
        conf_file = self.get_working_config()

        config = connector.PostgreConfig(conf_file.name)
        self.assertEqual(config.host, "config_host")
        self.assertEqual(config.user, "config_user")
        self.assertEqual(config.password, "config_password")

    @mock.patch.dict(
        "os.environ",
        {
            "DATA_EXTRACTOR_DATABASE_PASSWORD": "env_password",
        },
        clear=True,
    )
    def test_config_env_override_config_file(self):
        conf_file = self.get_working_config()

        config = connector.PostgreConfig(conf_file.name)
        self.assertEqual(config.host, "config_host")
        self.assertEqual(config.user, "config_user")
        self.assertEqual(config.password, "env_password")


if __name__ == "__main__":
    unittest.main()
