import sys

__version__ = 'v0.1'

if sys.version_info < (3,):
    raise ImportError('Please use python3')