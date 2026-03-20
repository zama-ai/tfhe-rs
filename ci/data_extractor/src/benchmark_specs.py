import enum

from exceptions import ParametersFormatNotSupported


class Backend(enum.StrEnum):
    """
    Represents different types of computation backends used in tfhe-rs.
    """

    CPU = "cpu"
    GPU = "gpu"
    HPU = "hpu"

    @staticmethod
    def from_str(backend_name):
        match backend_name.lower():
            case "cpu":
                return Backend.CPU
            case "gpu":
                return Backend.GPU
            case "hpu":
                return Backend.HPU
            case _:
                raise NotImplementedError(f"backend '{backend_name}' not supported")


class Layer(enum.StrEnum):
    """
    Represents different types of layers used in tfhe-rs.
    """

    HLApi = "hlapi"
    Integer = "integer"
    Shortint = "shortint"
    CoreCrypto = "core_crypto"
    Wasm = "wasm"

    @staticmethod
    def from_str(layer_name):
        match layer_name.lower():
            case "hlapi":
                return Layer.HLApi
            case "integer":
                return Layer.Integer
            case "shortint":
                return Layer.Shortint
            case "core_crypto":
                return Layer.CoreCrypto
            case "wasm":
                return Layer.Wasm
            case _:
                raise NotImplementedError(f"layer '{layer_name}' not supported")


class RustType(enum.Enum):
    """
    Represents different integer Rust types used in tfhe-rs.
    """

    FheUint2 = 2
    FheUint4 = 4
    FheUint6 = 6
    FheUint8 = 8
    FheUint10 = 10
    FheUint12 = 12
    FheUint14 = 14
    FheUint16 = 16
    FheUint32 = 32
    FheUint64 = 64
    FheUint128 = 128
    FheUint256 = 256
    FheUint512 = 512

    @staticmethod
    def from_int(value):
        match value:
            case 2:
                return RustType.FheUint2
            case 4:
                return RustType.FheUint4
            case 6:
                return RustType.FheUint6
            case 8:
                return RustType.FheUint8
            case 10:
                return RustType.FheUint10
            case 12:
                return RustType.FheUint12
            case 14:
                return RustType.FheUint14
            case 16:
                return RustType.FheUint16
            case 32:
                return RustType.FheUint32
            case 64:
                return RustType.FheUint64
            case 128:
                return RustType.FheUint128
            case 256:
                return RustType.FheUint256
            case 512:
                return RustType.FheUint512
            case _:
                raise NotImplementedError(f"Rust type '{value}' not supported")


ALL_RUST_INTEGER_TYPES = [
    RustType.FheUint2,
    RustType.FheUint4,
    RustType.FheUint8,
    RustType.FheUint16,
    RustType.FheUint32,
    RustType.FheUint64,
    RustType.FheUint128,
    RustType.FheUint256,
]


class CoreCryptoOperation(enum.StrEnum):
    """
    Represents different core crypto operations performed in tfhe-rs.
    The values are the ones displayed in the public benchmarks documentation.
    """

    KeySwitch = "KS"
    PBS = "PBS"
    MultiBitPBS = "MB-PBS"
    KeySwitchPBS = "KS - PBS"
    KeySwitchMultiBitPBS = "KS - MB-PBS"

    @staticmethod
    def from_str(operation_name):
        match operation_name.lower():
            case "keyswitch":
                return CoreCryptoOperation.KeySwitch
            case "pbs_mem_optimized" | "pbs":
                return CoreCryptoOperation.PBS
            case "multi_bit_pbs" | "multi_bit_deterministic_pbs":
                return CoreCryptoOperation.MultiBitPBS
            case "ks_pbs":
                return CoreCryptoOperation.KeySwitchPBS
            case "multi_bit_ks_pbs" | "multi_bit_deterministic_ks_pbs":
                return CoreCryptoOperation.KeySwitchMultiBitPBS
            case _:
                raise NotImplementedError(
                    f"core crypto operation '{operation_name}' not supported yet"
                )

    def display_name(self):
        """
        Return the human-friendly name recorded for a given operation.
        This name is parameter-independent.

        :return: The name as recorded by tfhe-benchmark crate
        :rtype: str
        """
        match self:
            case CoreCryptoOperation.KeySwitch:
                return "ks"
            case CoreCryptoOperation.PBS:
                return "pbs"
            case CoreCryptoOperation.MultiBitPBS:
                return "pbs"
            case CoreCryptoOperation.KeySwitchPBS:
                return "ks-pbs"
            case CoreCryptoOperation.KeySwitchMultiBitPBS:
                return "ks-pbs"
            case _:
                raise NotImplementedError(
                    f"display name for {self} not implemented yet"
                )


class SignFlavor(enum.StrEnum):
    """
    Represents the sign of integer benchmarks.
    """

    Signed = "signed"
    Unsigned = "unsigned"


class OperandType(enum.StrEnum):
    """
    Represents the type of operand use in a benchmark.
    Ciphertext means encrypted-encrypted operation.
    PlainText means encrypted-plaintext operation.
    """

    CipherText = "CipherText"  # As represented in the database
    PlainText = "PlainText"


class PBSKind(enum.StrEnum):
    """
    Represents the kind of parameter set used for Programmable Bootstrapping operation.
    """

    Classical = "classical"
    MultiBit = "multi_bit"
    Any = "any"  # Special variant used when user doesn't care about the PBS kind

    @staticmethod
    def from_str(pbs_name):
        match pbs_name.lower():
            case "classical":
                return PBSKind.Classical
            case "multi_bit":
                return PBSKind.MultiBit
            case "any":
                return PBSKind.Any
            case _:
                raise NotImplementedError(f"PBS kind '{pbs_name}' not supported")


class NoiseDistribution(enum.StrEnum):
    """
    Represents the noise distribution used in the parameter set.
    """

    Gaussian = "gaussian"
    TUniform = "tuniform"

    @staticmethod
    def from_str(distrib_name):
        match distrib_name.lower():
            case "gaussian":
                return NoiseDistribution.Gaussian
            case "tuniform":
                return NoiseDistribution.TUniform
            case _:
                raise NotImplementedError(
                    f"noise distribution '{distrib_name}' not supported"
                )


class ErrorFailureProbability(enum.IntEnum):
    """
    Represents the error failure probability associated with a parameter set.
    """

    TWO_MINUS_40 = 40
    TWO_MINUS_64 = 64
    TWO_MINUS_128 = 128

    @staticmethod
    def from_param_name(name):
        parts = name.split("_")
        for part in parts:
            if not part.startswith("2M"):
                continue

            try:
                pfail_int_value = int(part.lstrip("2M"))
            except ValueError:
                raise ValueError(f"Could not parse p-fail value as integer in '{name}'")

            match pfail_int_value:
                case 40:
                    return ErrorFailureProbability.TWO_MINUS_40
                case 64:
                    return ErrorFailureProbability.TWO_MINUS_64
                case 128:
                    return ErrorFailureProbability.TWO_MINUS_128
                case _:
                    raise NotImplementedError(
                        f"error failure probability '{part}' not supported yet"
                    )
        else:
            raise ValueError(f"Could not find p-fail value in '{name}'")

    def to_str(self):
        match self:
            case ErrorFailureProbability.TWO_MINUS_40:
                return "2M40"
            case ErrorFailureProbability.TWO_MINUS_64:
                return "2M64"
            case ErrorFailureProbability.TWO_MINUS_128:
                return "2M128"
            case _:
                raise ValueError(
                    f"error failure probability str conversion '{self}' not supported yet"
                )

    def __str__(self):
        return self.to_str()


class BenchType(enum.StrEnum):
    Latency = "Latency"
    Throughput = "Throughput"
    Both = "Both"

    @staticmethod
    def from_str(bench_type):
        match bench_type.lower():
            case "latency":
                return BenchType.Latency
            case "throughput":
                return BenchType.Throughput
            case "both":
                return BenchType.Both
            case _:
                raise NotImplementedError(f"BenchType '{bench_type}' not supported")


class BenchSubset(enum.StrEnum):
    All = "all"
    Erc20 = "erc20"
    Zk = "zk"

    @staticmethod
    def from_str(bench_subset):
        match bench_subset.lower():
            case "all":
                return BenchSubset.All
            case "erc20":
                return BenchSubset.Erc20
            case "zk":
                return BenchSubset.Zk
            case _:
                raise ValueError(f"BenchSubset '{bench_subset}' not supported")


class ZKOperation(enum.StrEnum):
    """
    Operations names mapped to their display in the public documentation.
    """

    Proof = "Proving"
    Verify = "Verifying"
    VerifyAndExpand = "Verify + expand"

    @staticmethod
    def from_str(op_name):
        match op_name.lower().rsplit("pke_zk_")[-1]:
            case "proof":
                return ZKOperation.Proof
            case "verify":
                return ZKOperation.Verify
            case "verify_and_expand":
                return ZKOperation.VerifyAndExpand
            case _:
                raise ValueError(f"ZK operation '{op_name}' not supported")


class ZKComputeLoad(enum.StrEnum):
    Proof = "slow proof / fast verify"
    Verify = "fast proof / slow verify"

    @staticmethod
    def from_str(load):
        match load.lower():
            case "proof":
                return ZKComputeLoad.Proof
            case "verify":
                return ZKComputeLoad.Verify
            case _:
                raise ValueError(f"ZK compute load '{load}' not supported")

    def fs_safe_str(self):
        return self.value.replace(" ", "_").replace("/", "and")


class ParamsDefinition:
    """
    Represents a parameter definition for specific cryptographic settings.

    The class `ParamsDefinition` is designed to parse and manage parameters derived from
    a specified parameter name. It facilitates comparison, representation, and hashing of
    parameter configurations. Parameters related to message size, carry size, noise characteristics,
    failure probabilities, and other functionalities are extracted and stored for streamlined
    usage across the system.

    :param param_name: The raw name of the parameter set.
    :type param_name: str
    """

    def __init__(self, param_name: str):
        self.message_size = None
        self.carry_size = None
        self.pbs_kind = None
        self.grouping_factor = None
        self.noise_distribution = None
        self.atomic_pattern = None
        self.p_fail = None
        self.version = None
        self.details = {}

        self._parse_param_name(param_name)

    def __eq__(self, other):
        return (
            self.message_size == other.message_size
            and self.carry_size == other.carry_size
            and self.pbs_kind == other.pbs_kind
            and self.grouping_factor == other.grouping_factor
            and self.noise_distribution == other.noise_distribution
            and self.atomic_pattern == other.atomic_pattern
            and self.p_fail == other.p_fail
            and self.version == other.version
            and self.details == other.details
        )

    def __lt__(self, other):

        return (
            self.message_size < other.message_size
            and self.carry_size < other.carry_size
            and self.p_fail < other.p_fail
        )

    def __hash__(self):
        return hash(
            (
                self.message_size,
                self.carry_size,
                self.pbs_kind,
                self.grouping_factor,
                self.noise_distribution,
                self.atomic_pattern,
                self.p_fail,
                self.version,
            )
        )

    def __repr__(self):
        return f"ParamsDefinition(message_size={self.message_size}, carry_size={self.carry_size}, pbs_kind={self.pbs_kind}, grouping_factor={self.grouping_factor}, noise_distribution={self.noise_distribution}, atomic_pattern={self.atomic_pattern}, p_fail={self.p_fail}, version={self.version}, details={self.details})"

    def _parse_param_name(self, param_name: str) -> None:
        split_params = param_name.split("_")

        if split_params[0].startswith("V"):
            minor_version = split_params.pop(1)
            major_version = split_params.pop(0).strip("V")
            self.version = major_version + "_" + minor_version

        # Use to know if a parameter set is a derivative of a compute one (e.g. compression parameters)
        params_variation_parts = []
        for part in split_params:
            if part == "PARAM":
                self.details["variation"] = "_".join(params_variation_parts)
                break

            params_variation_parts.append(part)

        try:
            self.p_fail = ErrorFailureProbability.from_param_name(param_name)
            pfail_index = split_params.index(self.p_fail.to_str())
        except ValueError or NotImplementedError:
            # Default error probability may not be shown in the name
            self.p_fail = ErrorFailureProbability.TWO_MINUS_128
            pfail_index = None

        if pfail_index:
            noise_distribution_index = pfail_index - 1
            self.noise_distribution = NoiseDistribution.from_str(
                split_params[noise_distribution_index]
            )
        else:
            # Default noise distribution may not be shown in the name
            self.noise_distribution = NoiseDistribution.TUniform
            noise_distribution_index = None

        try:
            self.message_size = int(split_params[split_params.index("MESSAGE") + 1])
            carry_size_index = split_params.index("CARRY") + 1
            self.carry_size = int(split_params[carry_size_index])
            self.atomic_pattern = "_".join(
                split_params[carry_size_index + 1 : noise_distribution_index]
            )
        except ValueError:
            # Might be a Boolean parameters set
            raise ParametersFormatNotSupported(param_name)

        try:
            if noise_distribution_index:
                self.atomic_pattern = "_".join(
                    split_params[carry_size_index + 1 : noise_distribution_index]
                )
            else:
                self.atomic_pattern = "_".join(split_params[carry_size_index + 1 :])
        except ValueError:
            # Might be a Boolean parameters set
            raise ParametersFormatNotSupported(param_name)

        try:
            self.details["trailing_details"] = "_".join(split_params[pfail_index + 1 :])
        except IndexError:
            # No trailing details
            pass

        try:
            # This is a multi-bit parameters set
            self.grouping_factor = int(split_params[split_params.index("GROUP") + 1])
            self.pbs_kind = PBSKind.MultiBit
        except ValueError:
            # This is a classical parameters set
            self.pbs_kind = PBSKind.Classical


class BenchDetails:
    """
    Represents the details of a benchmark test for different layers.

    This class is designed to parse benchmark information, extract meaningful
    details such as operation name, parameters, and relevant configuration
    based on the layer type. It allows for comparison between different benchmark
    details and outputs structured information for representation or hashing.

    :param layer: The layer the benchmark pertains to.
    :type layer: Layer
    :param bench_full_name: Complete name of the benchmark operation.
    :type bench_full_name: str
    :param bit_size: The bit size associated with the benchmark.
    :type bit_size: int
    """

    def __init__(self, layer: Layer, bench_full_name: str, bit_size: int):
        self.layer = layer

        self.bench_type = BenchType.Latency
        self.operation_name = None
        self.bit_size = bit_size
        self.params = None
        # Only relevant for Integer layer
        self.sign_flavor = None
        # Only relevant for HLApi layer
        self.rust_type = None
        self.case_variation = None

        self.parse_test_name(bench_full_name)

    def __repr__(self):
        return f"BenchDetails(layer={self.layer.value}, type={self.bench_type}, operation_name={self.operation_name}, bit_size={self.bit_size}, params={self.params}, sign={self.sign_flavor or 'N/A'}, case={self.case_variation or 'N/A'})"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return (
            self.layer == other.layer
            and self.bench_type == other.bench_type
            and self.operation_name == other.operation_name
            and self.bit_size == other.bit_size
            and self.params == other.params
            and self.sign_flavor == other.sign_flavor
            and self.rust_type == other.rust_type
            and self.case_variation == other.case_variation
        )

    def __hash__(self):
        return hash(
            (
                self.layer,
                self.bench_type,
                self.operation_name,
                self.bit_size,
                self.params,
                self.rust_type,
                self.sign_flavor,
                self.case_variation,
            )
        )

    def parse_test_name(self, name) -> None:
        """
        Parse test name to split relevant parts.

        :param name: The raw test name.
        :type name: str

        :return: None
        """
        parts = name.split("::")

        if "throughput" in parts:
            self.bench_type = BenchType.Throughput

        for part in parts:
            if "PARAM" in part:
                self.params = part.partition("_mean")[0]
                break

        match self.layer:
            case Layer.Integer:
                op_name_index = 2 if parts[1] in ["cuda", "hpu", "zk"] else 1

                if self.params and not parts[-1].startswith(self.params):
                    self.case_variation = parts[-1].partition("_mean")[0]

                if parts[op_name_index] == "signed":
                    op_name_index += 1
                    self.sign_flavor = SignFlavor.Signed
                    self.operation_name = parts[op_name_index]
                elif parts[op_name_index] == "unsigned":
                    # This is a pattern used by benchmark run on CUDA
                    op_name_index += 1
                    self.sign_flavor = SignFlavor.Unsigned
                    self.operation_name = parts[op_name_index]
                else:
                    self.sign_flavor = SignFlavor.Unsigned
                    self.operation_name = parts[op_name_index]
                    if not self.params:
                        self.params = parts[op_name_index + 1]
                    if "compression" in parts[op_name_index]:
                        self.rust_type = "_".join(
                            (parts[op_name_index], parts[-1].split("_")[0])
                        )
            case Layer.CoreCrypto:
                self.operation_name = parts[2] if parts[1] == "cuda" else parts[1]
            case Layer.HLApi:
                if parts[1] in ["cuda", "hpu"]:
                    if "PARAM_" in parts[-2]:
                        # Case for arithmetic operations (add, sub, mul,...)
                        self.operation_name = "::".join(parts[2:-2])
                    else:
                        # Case for higher-level operation (erc20 transfer, dex,...)
                        self.operation_name = "::".join(parts[2:-1])
                else:
                    if "PARAM_" in parts[-2]:
                        # Case for arithmetic operations (add, sub, mul,...)
                        self.operation_name = "::".join(parts[1:-2])
                    else:
                        # Case for higher-level operation (erc20 transfer, dex,...)
                        self.operation_name = "::".join(parts[1:-1])
                self.rust_type = parts[-1].partition("_mean")[0]
            case Layer.Shortint:
                self.operation_name = parts[1]
            case Layer.Wasm:
                op_name_index = 2 if parts[1] in ["cuda", "hpu", "zk"] else 1
                self.operation_name = parts[op_name_index]

                if self.params and not parts[-1].startswith(self.params):
                    self.case_variation = parts[-1].partition("_mean")[0]
            case _:
                raise NotImplementedError(
                    f"layer '{self.layer}' not supported yet for name parsing"
                )

    def get_params_definition(self) -> ParamsDefinition:
        """
        Returns the definition of parameters based on the current instance's parameters.

        :return: A ParamsDefinition object that encapsulates the parameter definition.
        :rtype: ParamsDefinition
        """
        return ParamsDefinition(self.params)
