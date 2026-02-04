import configparser
import datetime
import os
import pathlib

import psycopg2
from benchmark_specs import (
    Backend,
    BenchDetails,
    BenchType,
    Layer,
    OperandType,
    PBSKind,
)
from config import UserConfig
from exceptions import NoDataFound


class PostgreConfig:
    """
    Represents the configuration to connect to a PostgreSQL database.

    This class is designed to manage and load PostgreSQL database credentials
    from a configuration file and override them with environment variables if available.

    :param path: Path to the configuration file.
    :type path: str, optional

    :ivar host: Host address of the PostgreSQL database.
    :type host: str
    :ivar user: Username for connecting to the PostgreSQL database.
    :type user: str
    :ivar password: Password for connecting to the PostgreSQL database.
    :type password: str
    """

    def __init__(self, path: str = None):
        self.host = None
        self.user = None
        self.password = None

        if path:
            self._from_config_file(path)

        self._override_with_env()

    def _from_config_file(self, path):
        """
        Parse configuration file containing credentials to Postgre database.

        :param path: path to the configuration file as :class:`str`

        :return: parsed file as :class:`configparser.ConfigParser`
        """
        path = pathlib.Path(path)
        conf = configparser.ConfigParser()
        conf.read(path)

        for option_name in ("user", "password", "host"):
            try:
                attr_value = conf.get("postgre", option_name)
            except ValueError:
                print(f"Cannot find mandatory option '{option_name}' in config file")
                raise

            setattr(self, option_name, attr_value)

    def _override_with_env(self):
        self.host = os.environ.get("DATA_EXTRACTOR_DATABASE_HOST", self.host)
        self.user = os.environ.get("DATA_EXTRACTOR_DATABASE_USER", self.user)
        self.password = os.environ.get(
            "DATA_EXTRACTOR_DATABASE_PASSWORD", self.password
        )


class PostgreConnector:
    def __init__(self, conf: PostgreConfig):
        """
        Initializes the class with a configuration object.

        :param conf: The configuration object used to set up
                     the connection or relevant settings.
        :type conf: PostgreConfig
        """
        self.conf = conf
        self._conn = None

    def __del__(self):
        if self._conn:
            # Avoid dandling connection on server side.
            self._conn.close()

    def connect_to_database(self, dbname: str):
        """
        Create a connection to a Postgre instance.

        :param dbname: Name of the database to connect to.
        :type dbname: str
        """
        print("Connecting to database... ", end="", flush=True)
        start_date = datetime.datetime.now()

        try:
            conn = psycopg2.connect(
                dbname=dbname,
                user=self.conf.user,
                password=self.conf.password,
                host=self.conf.host,
            )
        except psycopg2.Error as err:
            print(f"Failed to connect to Postgre database")
            raise
        else:
            elapsed = (datetime.datetime.now() - start_date).total_seconds()
            print(f"connected in {elapsed}s")

        self._conn = conn

    def close(self):
        """
        Close the connection to the database.

        :return: None
        """
        self._conn.close()
        self._conn = None

    def fetch_benchmark_data(
        self,
        user_config: UserConfig,
        operand_type: OperandType = None,
        operation_filter: list = None,
        layer: Layer = None,
        branch: str = None,
        name_suffix: str = None,
        last_value_only: bool = True,
    ) -> dict[BenchDetails, list[int]]:
        """
        Fetches benchmark data from the database based on various filtering criteria.

        Filters and constructs a query based on the provided user configuration and optional
        parameters such as operand type, operation filters, layer, and others. It retrieves
        specific benchmark metrics like test names, bit sizes, metric values, and their last
        inserted values. The data is fetched for a given hardware, backend, branch, and project
        version, or within a computed time range.

        :param user_config: User's configuration specifying backend, hardware, branch, layer,
            project version, PBS kind, benchmark date, and time span.
        :type user_config: UserConfig
        :param operand_type: Optional operand type filter.
        :type operand_type: OperandType, optional
        :param operation_filter: Optional list of operation name filters for partial test name matching.
        :type operation_filter: list, optional
        :param layer: Optional tfhe-rs layer filter
        :type layer: Layer, optional
        :param branch: Optional branch filter, defaulting to the user's head branch if not specified.
        :type branch: str, optional
        :param name_suffix: Suffix to match the test names.
        :type name_suffix: str, optional
        :param last_value_only: A flag indicating whether to fetch only the most recent metric value for each benchmark.
        :type last_value_only: bool

        :return: Fetched benchmark data filtered and formatted as per the query.
        :rtype: dict[BenchDetails, list[int]]
        """
        backend = user_config.backend
        branch = branch.lower() if branch else user_config.head_branch
        hardware = user_config.hardware
        layer = layer if layer else user_config.layer
        version = user_config.project_version
        pbs_kind = user_config.pbs_kind
        name_suffix = name_suffix if name_suffix else user_config.name_suffix

        timestamp_range_end = user_config.bench_date
        timestamp = datetime.datetime.fromisoformat(timestamp_range_end)
        time_span_delta = datetime.timedelta(days=user_config.time_span_days)
        timestamp_range_start = datetime.datetime.isoformat(timestamp - time_span_delta)
        if layer == Layer.CoreCrypto:
            # Before this date we used another name format that is not parsable by this tool.
            cutoff_date = "2024-02-28T00:00:00"
            timestamp_range_start = max(cutoff_date, timestamp_range_start)

        filters = list()

        filters.append(f"h.name = '{hardware}'")
        filters.append(f"bk.name = '{backend}'")
        filters.append(f"b.name = '{branch}'")

        name_suffix = f"\\{name_suffix}"
        match backend:
            case Backend.CPU:
                filters.append(f"test.name LIKE '{layer}::%{name_suffix}'")
            case Backend.GPU:
                filters.append(f"test.name LIKE '{layer}::cuda::%{name_suffix}'")
            case Backend.HPU:
                name_suffix = f"_mean"
                filters.append(f"test.name LIKE '{layer}::hpu::%{name_suffix}'")

        if version:
            filters.append(f"pv.name = '{version}'")
        else:
            filters.append(f"m.insert_time >= '{timestamp_range_start}'")
            filters.append(f"m.insert_time <= '{timestamp_range_end}'")

        # First iteration to fetch only default operations
        filters.append("test.name NOT SIMILAR TO '%(smart|unchecked)_%'")
        match pbs_kind:
            case PBSKind.Classical:
                filters.append(
                    "p.crypto_parameters_alias NOT SIMILAR TO '%_MULTI_BIT_%'"
                )
            case PBSKind.MultiBit:
                filters.append("p.crypto_parameters_alias SIMILAR TO '%_MULTI_BIT_%'")
            case PBSKind.Any:
                # No need to add a filter
                pass

        if operand_type:
            filters.append(f"p.operand_type = '{operand_type.value}'")

        if operation_filter:
            conditions = [
                f"test.name LIKE '%::{op_name}::%'" for op_name in operation_filter
            ]
            filters.append("({})".format(" OR ".join(conditions)))

        match user_config.bench_type:
            case BenchType.Latency:
                filters.append("test.name NOT SIMILAR TO '%::throughput::%'")
            case BenchType.Throughput:
                filters.append("test.name LIKE '%::throughput::%'")
            case BenchType.Both:
                # No need to add a filter.
                pass

        select_parts = (
            "SELECT",
            "test.name as test,",
            "p.bit_size as bit_size,",
            "m.value as value,",
            "m.insert_time,",
            "LAST_VALUE (value)",
            "OVER (PARTITION BY test.name ORDER BY m.insert_time RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) last_value",
            "FROM benchmark.metrics as m",
            "LEFT JOIN benchmark.project_version as pv ON m.project_version_id = pv.id",
            "LEFT JOIN benchmark.hardware as h ON m.hardware_id = h.id",
            "LEFT JOIN benchmark.backend as bk ON m.backend_id = bk.id",
            "LEFT JOIN benchmark.branch as b ON b.id = m.branch_id",
            "LEFT JOIN benchmark.test as test ON test.id = m.test_id",
            "LEFT JOIN benchmark.parameters as p ON p.id = m.parameters_id",
        )

        sql_string = format(
            "{} WHERE {} GROUP BY test, bit_size, value, m.insert_time ORDER BY m.insert_time DESC"
        ).format(" ".join(select_parts), " AND ".join(filters))

        return self._fetch_data(
            sql_string,
            version,
            timestamp_range_start,
            timestamp_range_end,
            hardware,
            layer,
            last_value_only,
        )

    def _fetch_data(
        self,
        sql_string,
        version,
        timestamp_range_start,
        timestamp_range_end,
        hw,
        layer: Layer,
        last_value_only: bool,
    ) -> dict[BenchDetails, list[int]]:
        with self._conn.cursor() as curs:
            start = datetime.datetime.now()
            print(f"Fetching data (hardware: {hw}, layer: {layer.value})...", end="")

            curs.execute(sql_string)
            lines = curs.fetchall()

            end = datetime.datetime.now()
            print(f"done in {(end - start).total_seconds()}s")

            results = dict()

            if not lines:
                if version:
                    msg = f"no data found under commit hash '{version}'"
                else:
                    msg = f"no data found in date range [{timestamp_range_start}, {timestamp_range_end}]"
                raise NoDataFound(msg)

            for line in lines:
                bit_width = line[1]

                bench_details = BenchDetails(layer, line[0], bit_width)
                value = line[-1] if last_value_only else line[-3]
                try:
                    timings = results[bench_details]
                    if last_value_only:
                        continue
                    else:
                        timings.append(value)
                except KeyError:
                    results[bench_details] = [value]

        return results
