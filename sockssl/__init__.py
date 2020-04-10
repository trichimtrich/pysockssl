import sys

__version__ = '0.2'

if sys.version_info < (3,):
    raise ImportError('Please use python3')