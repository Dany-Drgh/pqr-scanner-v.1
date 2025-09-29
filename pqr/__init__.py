## `pqr/__init__.py`
import sys

__all__ = ["__version__"]
__version__ = "0.0.1"
if sys.version_info < (3, 11):
    raise RuntimeError("pqr requires Python 3.11+")
