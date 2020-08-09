# The real importing is done in src/__init__.py.
# This file allows an external program to do this:
# from statelessgpgpython2 import gpg
# Note: We can't put the import statements in here and then use
# "from .pytestImports import *" in e.g. pytest test files, because then we would get
# the "Attempted relative import in non-package" error.
# pytest -sq is usually run from the top-most directory.
from src import *
