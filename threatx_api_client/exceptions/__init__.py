class TXAPIError(Exception):
    """Common TX API Client exception class."""
    pass


class TXAPIIncorrectTokenError(TXAPIError):
    """TX API Client exception class for incorrect API token provided."""
    pass


class TXAPIIncorrectCommandError(TXAPIError):
    """TX API Client exception class for incorrect command provided."""
    pass


class TXAPIResponseError(TXAPIError):
    """TX API Client response error exception class."""
    pass
