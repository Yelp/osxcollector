# -*- coding: utf-8 -*-
#
# All exceptions thrown by the osxcollector.output_filters module
#


class OutputFilterError(Exception):
    pass


class MissingConfigError(OutputFilterError):

    """An error to throw when configuration is missing"""
    pass


class BadDomainError(OutputFilterError):

    """An error to throw when a domain is invalid."""
    pass


class InvalidRequestError(OutputFilterError):

    """Raised by MultiRequest when it can't figure out how to make a request."""
    pass
