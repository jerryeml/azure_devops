class AzureExcepiton(Exception):
    pass


class OSCETaskError(Exception):
    pass


class OSCEWinRMCommandTimeout(Exception):
    pass


class OSCEWinRMOperationTimeout(Exception):
    pass


class OSCEWinRMIllegalOperation(Exception):
    pass


class OSCEWinRMClassNotRegister(Exception):
    pass


class OSCEWinRMTransportException(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class TargetIsNotExistError(Exception):
    pass
