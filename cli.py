#!/usr/bin/python3




# Imports
import os
import sys
import argparse
import logging




# Local imports
# (Can't use relative imports because this is a top-level script)
import stateless_gpg




# Shortcuts
gpg = stateless_gpg.code.stateless_gpg.gpg




# Notes:
# - Using keyword function arguments, each of which is on its own line,
# makes Python code easier to maintain. Arguments can be changed and
# rearranged much more easily.




# Set up logger for this module. By default, it logs at ERROR level.
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
logger.setLevel(logging.ERROR)
log = logger.info
deb = logger.debug




def setup(
    log_level = 'error',
    debug = False,
    log_timestamp = False,
    log_file = None,
    ):
  logger_name = 'cli'
  # Configure logger for this module.
  stateless_gpg.util.module_logger.configure_module_logger(
    logger = logger,
    logger_name = logger_name,
    log_level = log_level,
    debug = debug,
    log_timestamp = log_timestamp,
    log_file = log_file,
  )
  deb('Setup complete.')
  # Configure logging levels for stateless_gpg package.
  # By default, without setup, it produces no log output.
  # Optionally, the package could be configured here to use a different log level, by e.g. passing in 'error' instead of log_level.
  stateless_gpg.setup(
    log_level = log_level,
    debug = debug,
    log_timestamp = log_timestamp,
    log_file = log_file,
  )




def main():

  parser = argparse.ArgumentParser(
    description='Command-Line Interface (CLI) for using the stateless_gpg package.'
  )

  parser.add_argument(
    '-t', '--task',
    help="Task to perform (default: '%(default)s').",
    default='hello',
  )

  parser.add_argument(
    '-l', '--logLevel', type=str, dest='log_level',
    choices=['debug', 'info', 'warning', 'error'],
    help="Choose logging level (default: '%(default)s').",
    default='error',
  )

  parser.add_argument(
    '-d', '--debug',
    action='store_true',
    help="Sets logLevel to 'debug'. This overrides --logLevel.",
  )

  parser.add_argument(
    '-s', '--logTimestamp', dest='log_timestamp',
    action='store_true',
    help="Choose whether to prepend a timestamp to each log line.",
  )

  parser.add_argument(
    '-x', '--logToFile', dest='log_to_file',
    action='store_true',
    help="Choose whether to save log output to a file.",
  )

  parser.add_argument(
    '-z', '--logFile', dest='log_file',
    help="The path to the file that log output will be written to.",
    default='log_stateless_gpg.txt',
  )

  a = parser.parse_args()

  # Check and analyse arguments.
  if not a.log_to_file:
    a.log_file = None

  # Setup
  setup(
    log_level = a.log_level,
    debug = a.debug,
    log_timestamp = a.log_timestamp,
    log_file = a.log_file,
  )

  # Run top-level function (i.e. the appropriate task).
  tasks = """
sign verify encrypt decrypt
gpg_name
test_sign_and_verify test_sign_and_verify_failure
test_encrypt_and_decrypt test_encrypt_and_decrypt_failure
""".split()
  if a.task not in tasks:
    msg = "Unrecognised task: {}".format(a.task)
    msg += "\nTask list: {}".format(tasks)
    stop(msg)
  globals()[a.task](a)  # run task.




def sign(a):
  pass




def verify(a):
  pass




def encrypt(a):
  data = "hello world\n"
  log("data = " + data.strip())
  public_key_file = 'stateless_gpg/data/test_key_1_public_key.txt'
  with open(public_key_file) as f:
    public_key = f.read()
  ciphertext = gpg.encrypt_data(public_key, data)
  print(ciphertext)




def decrypt(a):
  pass




def gpg_name(a):
  gpg_cmd_name = gpg.get_available_gpg_command()
  print(gpg_cmd_name)




def test_sign_and_verify(a):
  data = "hello world\n"
  log("data = " + data.strip())
  private_key_file = 'stateless_gpg/data/test_key_1_private_key.txt'
  with open(private_key_file) as f:
    private_key = f.read()
  signature = gpg.make_signature(private_key, data)
  public_key_file = 'stateless_gpg/data/test_key_1_public_key.txt'
  with open(public_key_file) as f:
    public_key = f.read()
  result = gpg.verify_signature(public_key, data, signature)
  log("result = " + str(result))
  if not result:
    raise Exception("Failed to create and verify signature.")
  print("Signature created and verified. Signature was not saved to a file.")




def test_sign_and_verify_failure(a):
  # Create a signature.
  data = "hello world\n"
  log("data = " + data.strip())
  private_key_file = 'stateless_gpg/data/test_key_1_private_key.txt'
  with open(private_key_file) as f:
    private_key = f.read()
  signature = gpg.make_signature(private_key, data)
  # Verify the signature.
  public_key = "invalid key data"
  result = gpg.verify_signature(public_key, data, signature)
  log("result = " + str(result))
  if not result:
    raise Exception("Failed to create and verify signature.")
  print("Signature created and verified. Signature was not saved to a file.")




def test_encrypt_and_decrypt(a):
  # Encrypt some data.
  data = "hello world\n"
  log("data = " + data.strip())
  public_key_file = 'stateless_gpg/data/test_key_1_public_key.txt'
  with open(public_key_file) as f:
    public_key = f.read()
  ciphertext = gpg.encrypt_data(public_key, data)
  # Decrypt the data.
  private_key_file = 'stateless_gpg/data/test_key_1_private_key.txt'
  with open(private_key_file) as f:
    private_key = f.read()
  plaintext = gpg.decrypt_data(private_key, ciphertext)
  log("plaintext = " + plaintext.strip())
  success = plaintext == data
  if not success:
    raise Exception("Failed to encrypt and decrypt data.")
  print("Data encrypted and decrypted. Ciphertext was not saved to a file.")




def test_encrypt_and_decrypt_failure(a):
  # Encrypt some data.
  data = "hello world\n"
  log("data = " + data.strip())
  public_key_file = 'stateless_gpg/data/test_key_1_public_key.txt'
  with open(public_key_file) as f:
    public_key = f.read()
  ciphertext = gpg.encrypt_data(public_key, data)
  # Decrypt the data.
  private_key = "invalid key data"
  plaintext = gpg.decrypt_data(private_key, ciphertext)
  log("plaintext = " + str(plaintext))
  success = plaintext == data
  if not success:
    raise Exception("Failed to encrypt and decrypt data.")
  print("Data encrypted and decrypted. Ciphertext was not saved to a file.")





def stop(msg=None):
  if msg is not None:
    print(msg)
  import sys
  sys.exit()




if __name__ == '__main__':
  main()
