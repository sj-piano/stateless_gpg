# Imports
import os
import logging
import pkgutil




# Relative imports
from ..code.stateless_gpg import gpg




# Shortcuts
join = os.path.join




# Set up logger for this module.
logger = logging.getLogger(__name__)
log = logger.info
deb = logger.debug




# Notes:
# - "work directory" = directory that contains this file.
# - Running the command { stateless_gpg/test/test_stateless_gpg.py } in the work directory should load and run the tests in this file.
# - Run a specific test:
# -- pytest3 stateless_gpg/test/test_stateless_gpg.py::test_hello_world_signature_only
# - Run quietly:
# -- pytest3 -q stateless_gpg/test/test_stateless_gpg.py
# - Print log data during a single test:
# -- pytest3 -o log_cli=true --log-cli-level=INFO --log-format="%(levelname)s [%(lineno)s: %(funcName)s] %(message)s" stateless_gpg/test/test_stateless_gpg.py::test_hello_world
# -- This is very useful when you want to manually check the operation of the functions during the test.




def test_hello_world():
  data = "hello world\n"
  log("data = " + data.strip())
  private_key_file = '../data/test_key_1_private_key.txt'
  private_key_bytes = pkgutil.get_data(__name__, private_key_file)
  private_key = private_key_bytes.decode('ascii')
  signature = gpg.make_signature(private_key, data)
  public_key_file = '../data/test_key_1_public_key.txt'
  public_key_bytes = pkgutil.get_data(__name__, public_key_file)
  public_key = public_key_bytes.decode('ascii')
  result = gpg.verify_signature(public_key, data, signature)
  log("result = " + str(result))
  assert result == True


def test_hello_world_signature_only():
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  log("data = " + data.strip())
  signature_file = '../data/data1_signature_by_test_key_1.txt'
  signature = pkgutil.get_data(__name__, signature_file).decode('ascii')
  public_key_file = '../data/test_key_1_public_key.txt'
  public_key = pkgutil.get_data(__name__, public_key_file).decode('ascii')
  result = gpg.verify_signature(public_key, data, signature)
  log("result = " + str(result))
  assert result == True



