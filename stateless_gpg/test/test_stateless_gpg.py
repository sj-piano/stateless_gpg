# Imports
import pytest
import pkgutil




# Relative imports
from .. import code




# Shortcuts
gpg = code.stateless_gpg.gpg




# Setup for this file.
@pytest.fixture(autouse=True, scope='module')
def setup_module(pytestconfig):
  # If log_level is supplied to pytest in the commandline args, then use it to set up the logging in the application code.
  log_level = pytestconfig.getoption('log_cli_level')
  if log_level is not None:
    log_level = log_level.lower()
    code.setup(log_level = log_level)




# Notes:
# - Running the command { pytest3 stateless_gpg/test/test_stateless_gpg.py }
# in the package directory should load and run the tests in this file.
# - Run a specific test:
# -- pytest3 stateless_gpg/test/test_stateless_gpg.py::test_sign_and_verify
# - Run quietly:
# -- [all tests] pytest3 -q
# -- pytest3 -q stateless_gpg/test/test_stateless_gpg.py
# - Print log output in real-time during a single test:
# -- pytest3 -s --log-cli-level=INFO stateless_gpg/test/test_stateless_gpg.py::test_sign_and_verify
# --- Note the use of the pytest -s option. This will cause print statements in the test code itself to also produce output.




def test_sign_and_verify():
  # Create signature.
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + data.strip())
  private_key_file = '../data/test_key_1_private_key.txt'
  private_key = pkgutil.get_data(__name__, private_key_file).decode('ascii')
  signature = gpg.make_signature(private_key, data)
  # Verify signature.
  public_key_file = '../data/test_key_1_public_key.txt'
  public_key = pkgutil.get_data(__name__, public_key_file).decode('ascii')
  result = gpg.verify_signature(public_key, data, signature)
  assert result is True
  print("Signature created and verified.")





def test_verify():
  # Verify signature.
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + data.strip())
  signature_file = '../data/data1_signature_by_test_key_1.txt'
  signature = pkgutil.get_data(__name__, signature_file).decode('ascii')
  public_key_file = '../data/test_key_1_public_key.txt'
  public_key = pkgutil.get_data(__name__, public_key_file).decode('ascii')
  result = gpg.verify_signature(public_key, data, signature)
  assert result is True
  print("Signature verified.")









