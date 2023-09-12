class TXAPIException(Exception):
    pass


class TXAPIIncorrectEnvironment(TXAPIException):
    pass


class TXAPIIncorrectToken(TXAPIException):
    pass


class TXAPIIncorrectCommand(TXAPIException):
    pass


class TXAPIResponseError(TXAPIException):
    pass