class NoDataFound(RuntimeError):
    """
    Indicates that no data was found when an operation or search was performed.

    This exception should be raised to signal that a requested operation could not
    complete because the required data was unavailable. It is typically used in
    cases where returning an empty result might not be appropriate, and an
    explicit notice of failure is required.
    """

    pass


class ParametersFormatNotSupported(Exception):
    """
    Exception raised for unsupported parameter formats.
    """

    def __init__(self, param_name):
        super().__init__(f"Parameters format '{param_name}' not supported.")
