class MatrixError(Exception):
    """A generic Matrix error. Specific errors will subclass this."""
    pass


class MatrixUnexpectedResponse(MatrixError):
    """The home server gave an unexpected response. """
    def __init__(self, content=""):
        super(MatrixError, self).__init__(content)
        self.content = content


class MatrixRequestError(MatrixError):
    """ The home server returned an error response. """

    def __init__(self, code=0, content=""):
        super(MatrixRequestError, self).__init__("%d: %s" % (code, content))
        self.code = code
        self.content = content
