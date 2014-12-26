class InvalidMessageException(Exception):
    def __init__(self, message, exceptions = None):
        if exceptions:
            message = message + "%s" % exceptions[0]
        super(InvalidMessageException, self).__init__(message)