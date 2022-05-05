# Imports
import os
import pytest
import pkgutil
import shutil




# Relative imports
from .. import code




# Shortcuts
gpg = code.stateless_gpg.gpg
isdir = os.path.isdir




# Utility functions.
def cleanup():
  # This function deletes any directory that starts with ".stateless_gpg".
  # These directories are created, but not deleted, when we test for a failure.
  dirs = [x for x in os.listdir('.') if isdir(x)]
  for d in dirs:
    if d.startswith('.stateless_gpg'):
      shutil.rmtree(d)




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
# -- pytest3 stateless_gpg/test/test_stateless_gpg.py::test_verify
# - Run quietly:
# -- [all tests] pytest3 -q
# -- pytest3 -q stateless_gpg/test/test_stateless_gpg.py
# - Print log output in real-time during a single test:
# -- pytest3 -s --log-cli-level=INFO stateless_gpg/test/test_stateless_gpg.py::test_verify
# --- Note the use of the pytest -s option. This will cause print statements in the test code itself to also produce output.




def test_sign_and_verify():
  # Create signature.
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + repr(data))
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
  print("data = " + repr(data))
  signature_file = '../data/data1_signature_by_test_key_1.txt'
  signature = pkgutil.get_data(__name__, signature_file).decode('ascii')
  public_key_file = '../data/test_key_1_public_key.txt'
  public_key = pkgutil.get_data(__name__, public_key_file).decode('ascii')
  result = gpg.verify_signature(public_key, data, signature)
  assert result is True
  print("Signature verified.")




def test_verify_failure():
  # Verify signature using a different key.
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + repr(data))
  signature_file = '../data/data1_signature_by_test_key_1.txt'
  signature = pkgutil.get_data(__name__, signature_file).decode('ascii')
  public_key_file = '../data/morgan_industries_public_key.txt'
  public_key = pkgutil.get_data(__name__, public_key_file).decode('ascii')
  with pytest.raises(ValueError):
    result = gpg.verify_signature(public_key, data, signature)
  cleanup()
  print("Could not verify signature.")




def test_encrypt_and_decrypt():
  # Encrypt some data.
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + repr(data))
  public_key_file = '../data/test_key_1_public_key.txt'
  public_key = pkgutil.get_data(__name__, public_key_file).decode('ascii')
  ciphertext = gpg.encrypt_data(public_key, data)
  # Decrypt the data.
  private_key_file = '../data/test_key_1_private_key.txt'
  private_key = pkgutil.get_data(__name__, private_key_file).decode('ascii')
  plaintext = gpg.decrypt_data(private_key, ciphertext)
  print("plaintext = " + repr(plaintext))
  success = plaintext == data
  assert success is True




def test_decrypt():
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + repr(data))
  ciphertext_file = '../data/data1_encrypted_to_test_key_1.txt'
  ciphertext = pkgutil.get_data(__name__, ciphertext_file).decode('ascii')
  private_key_file = '../data/test_key_1_private_key.txt'
  private_key = pkgutil.get_data(__name__, private_key_file).decode('ascii')
  plaintext = gpg.decrypt_data(private_key, ciphertext)
  print("plaintext = " + repr(plaintext))
  success = plaintext == data
  assert success is True




def test_decrypt_failure():
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + repr(data))
  # Decrypt the data using a different key.
  ciphertext_file = '../data/data1_encrypted_to_test_key_1.txt'
  ciphertext = pkgutil.get_data(__name__, ciphertext_file).decode('ascii')
  private_key_file = '../data/morgan_industries_private_key.txt'
  private_key = pkgutil.get_data(__name__, private_key_file).decode('ascii')
  with pytest.raises(ValueError):
    plaintext = gpg.decrypt_data(private_key, ciphertext)
  cleanup()
  print('Could not decrypt data.')




def test_wrap_and_unwrap():
  # Wrap:
  # - We sign the data with the private key of the sender.
  # - Then we encrypt it to the public key of the recipient.
  # Unwrap:
  # - We unencrypt the data using the private key of the receiver.
  # - Then we verify the signature of the data using the public key of the sender.
  # Load data.
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + repr(data))
  # Load sender keys.
  sender_private_key_file = '../data/test_key_1_private_key.txt'
  sender_private_key = pkgutil.get_data(__name__, sender_private_key_file).decode('ascii')
  sender_public_key_file = '../data/test_key_1_public_key.txt'
  sender_public_key = pkgutil.get_data(__name__, sender_public_key_file).decode('ascii')
  # Load receiver keys.
  receiver_private_key_file = '../data/morgan_industries_private_key.txt'
  receiver_private_key = pkgutil.get_data(__name__, receiver_private_key_file).decode('ascii')
  receiver_public_key_file = '../data/morgan_industries_public_key.txt'
  receiver_public_key = pkgutil.get_data(__name__, receiver_public_key_file).decode('ascii')
  # Wrap and unwrap.
  wrapped_data = gpg.wrap_data(sender_private_key, receiver_public_key, data)
  unwrapped_data = gpg.unwrap_data(receiver_private_key, sender_public_key, wrapped_data)
  print("unwrapped_data = " + repr(unwrapped_data))
  success = unwrapped_data == data
  assert success is True




def test_unwrap():
  # Load data.
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + repr(data))
  wrapped_data_file = '../data/wrapped_data_from_test_key_1_to_morgan_industries.txt'
  wrapped_data = pkgutil.get_data(__name__, wrapped_data_file).decode('ascii')
  # Load sender public key.
  sender_public_key_file = '../data/test_key_1_public_key.txt'
  sender_public_key = pkgutil.get_data(__name__, sender_public_key_file).decode('ascii')
  # Load receiver private key.
  receiver_private_key_file = '../data/morgan_industries_private_key.txt'
  receiver_private_key = pkgutil.get_data(__name__, receiver_private_key_file).decode('ascii')
  # Unwrap data.
  unwrapped_data = gpg.unwrap_data(receiver_private_key, sender_public_key, wrapped_data)
  print("unwrapped_data = " + repr(unwrapped_data))
  success = unwrapped_data == data
  assert success is True




def test_unwrap_failure():
  # Load data.
  data_file = '../data/data1.txt'
  data = pkgutil.get_data(__name__, data_file).decode('ascii')
  print("data = " + repr(data))
  wrapped_data_file = '../data/wrapped_data_from_test_key_1_to_morgan_industries.txt'
  wrapped_data = pkgutil.get_data(__name__, wrapped_data_file).decode('ascii')
  # Load sender public key.
  sender_public_key_file = '../data/test_key_1_public_key.txt'
  sender_public_key = pkgutil.get_data(__name__, sender_public_key_file).decode('ascii')
  # Load an incorrect receiver private key.
  receiver_private_key_file = '../data/test_key_1_private_key.txt'
  receiver_private_key = pkgutil.get_data(__name__, receiver_private_key_file).decode('ascii')
  # Unwrap data.
  with pytest.raises(ValueError):
    plaintext = gpg.unwrap_data(receiver_private_key, sender_public_key, wrapped_data)
  cleanup()
  print('Could not unwrap data.')



