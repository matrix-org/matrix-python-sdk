import sys

if sys.version_info < (3, 5):
    collect_ignore = ["test_async_api.py"]
