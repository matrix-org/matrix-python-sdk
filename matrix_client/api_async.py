import sys

if sys.version_info < (3, 5):
    raise ValueError("The asyncio version of the api "
                     "is only supported on Python 3.5+")  # pragma: nocover
else:
    from ._api_async import AsyncHTTPAPI

    __all__ = ['AsyncHTTPAPI']
