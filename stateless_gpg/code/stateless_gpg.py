# Imports
import os
import shutil
import uuid
import subprocess
import logging




# Relative imports
from .. import util




# Shortcuts
join = os.path.join
v = util.validate




# Set up logger for this module. By default, it produces no output.
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
logger.setLevel(logging.ERROR)
log = logger.info
deb = logger.debug




# Notes:
# - Some GPG commands send output to stderr. Use 2>&1 to redirect this output to stdout.




def setup(
    log_level = 'error',
    debug = False,
    log_timestamp = False,
    log_file = None,
    ):
  # Configure logger for this module.
  util.module_logger.configure_module_logger(
    logger = logger,
    logger_name = __name__,
    log_level = log_level,
    debug = debug,
    log_timestamp = log_timestamp,
    log_file = log_file,
  )
  deb('Setup complete.')




class gpg(object):


  # This is a wrapper class. It's meant to be treated as if it were a module. Example:
  # from stateless_gpg import gpg
  # signature = gpg.make_signature(private_key, data)


  def __init__(self):
    pass


  # not used.
  @staticmethod
  def get_available_gpg_command_old_version():
    # We want the bash command that calls GPG 1.4.x.
    # (Not GPG 2.x)
    gpg_cmd_names = 'gpg gpgv1'.split()
    for name in gpg_cmd_names:
      if shell_tool_exists(name):
        output, exit_code = run_local_cmd(name + ' --version')
        if exit_code != 0:
          raise ValueError
        version_line = output.splitlines()[0]
        # Examples:
        # gpg (GnuPG) 1.4.20
        # gpg (GnuPG) 2.2.19
        # gpgv (GnuPG) 1.4.23
        version = version_line.split()[-1]
        major, minor, patch = version.split('.')
        if major == '1' and minor == '4':
          return name
    msg = "Tried each bash command in this list: {}".format(gpg_cmd_names)
    msg += ". None of them lead to GPG 1.4.x."
    raise ValueError(msg)


  @staticmethod
  def get_available_gpg_command():
    # Update: Everything appears to work fine with GPG 2.x.
    # Future: Create keys with GPG 2, see if everything still works.
    return 'gpg'


  @staticmethod
  def make_signature(private_key, data):
    gpg_cmd_name = gpg.get_available_gpg_command()
    gpg_dir_name = create_temp_directory()
    data_dir_name = create_temp_directory()
    private_key_file = join(data_dir_name, 'private_key.txt')
    with open(private_key_file, 'w') as f:
      f.write(private_key)
    data_file = join(data_dir_name, 'data.txt')
    with open(data_file, 'w') as f:
      f.write(data)
    permissions_cmd = 'chmod 700 {g}'.format(g=gpg_dir_name)
    run_local_cmd(permissions_cmd)
    # Import private key into tmp keyring.
    import_cmd = '{n} --no-default-keyring --homedir {g} --import {p} 2>&1'
    import_cmd = import_cmd.format(n=gpg_cmd_name, g=gpg_dir_name, p=private_key_file)
    run_local_cmd(import_cmd)
    # Sign the data using the private key.
    signature_file = join(data_dir_name, 'signature.txt')
    sign_cmd = '{n} --no-default-keyring --homedir {g} --output {s} --armor --detach-sign {d}'
    sign_cmd = sign_cmd.format(n=gpg_cmd_name, g=gpg_dir_name, s=signature_file, d=data_file)
    run_local_cmd(sign_cmd)
    with open(signature_file) as f:
      signature = f.read()
    shutil.rmtree(gpg_dir_name)
    shutil.rmtree(data_dir_name)
    log("GPG signature created.")
    return signature


  @staticmethod
  def verify_signature(public_key, data, signature):
    # Example GPG output: Bad signature
### BEGIN EXAMPLE
# gpg: no valid OpenPGP data found.
# [GNUPG:] NODATA 1
# [GNUPG:] NODATA 2
# gpg: the signature could not be verified.
# Please remember that the signature file (.sig or .asc)
# should be the first file given on the command line.
# Example GPG output: Good signature
# [GNUPG:] SIG_ID m6uSV9RYxObc294UbLSUetwlHJw 2020-08-08 1596924121
# [GNUPG:] GOODSIG 3375AE2D255344FE Test Key 1
# gpg: Good signature from "Test Key 1"
# [GNUPG:] VALIDSIG F90F200288C86F686D65E58C3375AE2D255344FE 2020-08-08 1596924121 0 4 0 1 2 00 F90F200288C86F686D65E58C3375AE2D255344FE
# [GNUPG:] TRUST_UNDEFINED
# gpg: WARNING: This key is not certified with a trusted signature!
# gpg:          There is no indication that the signature belongs to the owner.
# Primary key fingerprint: F90F 2002 88C8 6F68 6D65  E58C 3375 AE2D 2553 44FE
### END EXAMPLE
    gpg_cmd_name = gpg.get_available_gpg_command()
    gpg_dir_name = create_temp_directory()
    data_dir_name = create_temp_directory()
    public_key_file = join(data_dir_name, 'public_key.txt')
    with open(public_key_file, 'w') as f:
      f.write(public_key)
    data_file = join(data_dir_name, 'data.txt')
    with open(data_file, 'w') as f:
      f.write(data)
    signature_file = join(data_dir_name, 'signature.txt')
    with open(signature_file, 'w') as f:
      f.write(signature)
    permissions_cmd = 'chmod 700 {g}'.format(g=gpg_dir_name)
    run_local_cmd(permissions_cmd)
    # Import public key into tmp keyring.
    import_cmd = '{n} --no-default-keyring --homedir {g} --import {p} 2>&1'
    import_cmd = import_cmd.format(n=gpg_cmd_name, g=gpg_dir_name, p=public_key_file)
    run_local_cmd(import_cmd)
    # Verify the signature using the public key.
    verify_cmd = '{n} --no-default-keyring --homedir {g} --status-fd 1 --verify {s} {d} 2>&1'
    verify_cmd = verify_cmd.format(n=gpg_cmd_name, g=gpg_dir_name, s=signature_file, d=data_file)
    output, exit_code = run_local_cmd(verify_cmd)
    shutil.rmtree(gpg_dir_name)
    shutil.rmtree(data_dir_name)
    success = False
    for line in output.split('\n'):
      if 'Good signature from' in line:
        success = True
        break
    if success:
      log("GPG signature verified.")
    else:
      msg = "GPG failed to verify signature."
      msg += "\n- verify_cmd: {}".format(verify_cmd)
      msg += "\n- output: {}".format(output)
      raise ValueError(msg)
    return success


  # Utility method that returns a boolean.
  @staticmethod
  def signature_is_valid(public_key, data, signature):
    try:
      gpg.verify_signature(public_key, data, signature)
    except Exception as e:
      return False
    return True


  @staticmethod
  def encrypt_data(public_key, data):
    gpg_cmd_name = gpg.get_available_gpg_command()
    gpg_dir_name = create_temp_directory()
    data_dir_name = create_temp_directory()
    public_key_file = join(data_dir_name, 'public_key.txt')
    with open(public_key_file, 'w') as f:
      f.write(public_key)
    data_file = join(data_dir_name, 'data.txt')
    with open(data_file, 'w') as f:
      f.write(data)
    ciphertext_file = join(data_dir_name, 'ciphertext.txt')
    permissions_cmd = 'chmod 700 {g}'.format(g=gpg_dir_name)
    run_local_cmd(permissions_cmd)
    # Import public key into tmp keyring.
    import_cmd = '{n} --no-default-keyring --homedir {g} --import {p} 2>&1'
    import_cmd = import_cmd.format(n=gpg_cmd_name, g=gpg_dir_name, p=public_key_file)
    run_local_cmd(import_cmd)
    # Load fingerprint of public key.
    display_cmd = '{n} --no-default-keyring --homedir {g} --keyid-format long --fingerprint --list-keys'
    display_cmd = display_cmd.format(n=gpg_cmd_name, g=gpg_dir_name)
    output, exit_code = run_local_cmd(display_cmd)
# Example output:
# .stateless_gpg_891ec63978/pubring.gpg
# -------------------------------------
# pub   4096R/3375AE2D255344FE 2020-08-08
#       Key fingerprint = F90F 2002 88C8 6F68 6D65  E58C 3375 AE2D 2553 44FE
# uid                          Test Key 1
# sub   4096R/9F2F2255D3066E8E 2020-08-08
    fingerprint = None
    for line in output.splitlines():
      if 'Key fingerprint' in line:
        fingerprint = line.split(' = ')[1].replace(' ', '')
    if not fingerprint:
      raise ValueError
    # Encrypt the data, using the fingerprint to specify the recipient.
    # Note: "--trust-model always" allows the "--yes" option to work properly.
    encrypt_cmd = '{n} --no-default-keyring --homedir {g} --keyid-format long --output {c} --armor --recipient {f} --yes --trust-model always --encrypt {d}'
    encrypt_cmd = encrypt_cmd.format(n=gpg_cmd_name, g=gpg_dir_name, f=fingerprint, c=ciphertext_file, d=data_file)
    output, exit_code = run_local_cmd(encrypt_cmd)
    if exit_code != 0:
      msg = "Problem encountered while encrypting data."
      msg += "\n- encrypt_cmd: {}".format(encrypt_cmd)
      msg += "\n- output: {}".format(output)
      raise ValueError(msg)
    with open(ciphertext_file) as f:
      ciphertext = f.read()
    shutil.rmtree(gpg_dir_name)
    shutil.rmtree(data_dir_name)
    log("GPG ciphertext created.")
    return ciphertext


  @staticmethod
  def decrypt_data(private_key, ciphertext):
    gpg_cmd_name = gpg.get_available_gpg_command()
    gpg_dir_name = create_temp_directory()
    data_dir_name = create_temp_directory()
    private_key_file = join(data_dir_name, 'private_key.txt')
    with open(private_key_file, 'w') as f:
      f.write(private_key)
    ciphertext_file = join(data_dir_name, 'ciphertext.txt')
    with open(ciphertext_file, 'w') as f:
      f.write(ciphertext)
    permissions_cmd = 'chmod 700 {g}'.format(g=gpg_dir_name)
    run_local_cmd(permissions_cmd)
    # Import private key into tmp keyring.
    import_cmd = '{n} --no-default-keyring --homedir {g} --import {p} 2>&1'
    import_cmd = import_cmd.format(n=gpg_cmd_name, g=gpg_dir_name, p=private_key_file)
    run_local_cmd(import_cmd)
    # Decrypt the data, using the single private key in the tmp keyring.
    # Note the use of "2>&1". This GPG command sends some output to the stderr channel.
    plaintext_file = join(data_dir_name, 'data.txt')
    decrypt_cmd = '{n} --no-default-keyring --homedir {g} --status-fd 1 --keyid-format long --output {p} --decrypt {c} 2>&1'
    decrypt_cmd = decrypt_cmd.format(n=gpg_cmd_name, g=gpg_dir_name, p=plaintext_file, c=ciphertext_file)
    output, exit_code = run_local_cmd(decrypt_cmd)
# Example output:
# [GNUPG:] ENC_TO 9F2F2255D3066E8E 1 0
# [GNUPG:] GOOD_PASSPHRASE
# gpg: encrypted with 4096-bit RSA key, ID 9F2F2255D3066E8E, created 2020-08-08
#       "Test Key 1"
# [GNUPG:] BEGIN_DECRYPTION
# [GNUPG:] DECRYPTION_INFO 2 9
# [GNUPG:] PLAINTEXT 62 1626621126 data.txt
# [GNUPG:] PLAINTEXT_LENGTH 12
# [GNUPG:] DECRYPTION_OKAY
# [GNUPG:] GOODMDC
# [GNUPG:] END_DECRYPTION
    success = False
    for line in output.split('\n'):
      if 'DECRYPTION_OKAY' in line:
        success = True
        break
    if not success:
      msg = "GPG failed to decrypt ciphertext."
      msg += "\n- decrypt_cmd: {}".format(decrypt_cmd)
      msg += "\n- output: {}".format(output)
      raise ValueError(msg)
    with open(plaintext_file) as f:
      plaintext = f.read()
    shutil.rmtree(gpg_dir_name)
    shutil.rmtree(data_dir_name)
    log("GPG ciphertext decrypted.")
    return plaintext


  @staticmethod
  def get_key_details(key, key_type='public'):
    if key_type not in 'private public'.split():
      raise ValueError
    gpg_cmd_name = gpg.get_available_gpg_command()
    gpg_dir_name = create_temp_directory()
    data_dir_name = create_temp_directory()
    key_file = join(data_dir_name, 'key.txt')
    with open(key_file, 'w') as f:
      f.write(key)
    permissions_cmd = 'chmod 700 {g}'.format(g=gpg_dir_name)
    run_local_cmd(permissions_cmd)
    # Import key into tmp keyring.
    import_cmd = '{n} --no-default-keyring --homedir {g} --import {k} 2>&1'
    import_cmd = import_cmd.format(n=gpg_cmd_name, g=gpg_dir_name, k=key_file)
    run_local_cmd(import_cmd)
    # Load fingerprint of key.
    display_cmd = '{n} --no-default-keyring --homedir {g} --keyid-format long --fingerprint'
    if key_type == 'private':
      display_cmd += ' --list-secret-keys'
    if key_type == 'public':
      display_cmd += ' --list-keys'
    display_cmd = display_cmd.format(n=gpg_cmd_name, g=gpg_dir_name)
    output, exit_code = run_local_cmd(display_cmd)
    shutil.rmtree(gpg_dir_name)
    shutil.rmtree(data_dir_name)
    log("GPG key details retrieved.")
    return output


  @staticmethod
  def wrap_data(sender_private_key, receiver_public_key, data):
    # We sign the data with the private key of the sender.
    # Then we encrypt it to the public key of the recipient.
    signature = gpg.make_signature(sender_private_key, data)
    # We append the signature to the data.
    # Note: We don't use clearsign, because clearsign may alter the plaintext.
    signed_data = data + '\n' + signature
    wrapped_data = gpg.encrypt_data(receiver_public_key, signed_data)
    return wrapped_data


  @staticmethod
  def unwrap_data(receiver_private_key, sender_public_key, wrapped_data):
    # We unencrypt the data using the private key of the receiver.
    # Then we verify the signature of the data using the public key of the sender.
    signed_data = gpg.decrypt_data(receiver_private_key, wrapped_data)
    # From signed_data, extract data and signature.
    # Proceed through the output lines in reverse.
    lines = signed_data.splitlines()
    start_line_reverse_index = None
    for i, line in enumerate(reversed(lines)):
      if i == 0:
        if line != '-----END PGP SIGNATURE-----':
          raise ValueError
      if line == '-----BEGIN PGP SIGNATURE-----':
        start_line_reverse_index = i
        break
    if start_line_reverse_index is None:
      raise ValueError
    start_line_index = (len(lines) - 1) - start_line_reverse_index
    data_lines = lines[:start_line_index]
    signature_lines = lines[start_line_index:]
    data = '\n'.join(data_lines)
    signature = '\n'.join(signature_lines)
    result = gpg.verify_signature(sender_public_key, data, signature)
    return data




def create_temp_directory():
  # Start the directory name with a dot so that it's hidden.
  def new_dir_name():
    random_digits = str(uuid.uuid4())[-10:]
    return '.stateless_gpg_' + random_digits
  while True:
    name = new_dir_name()
    if not os.path.exists(name):
      break
  os.mkdir(name)
  return name




def shell_tool_exists(tool):
  if ' ' in tool:
    raise ValueError
  tool = 'command -v {}'.format(tool)
  output, exit_code = run_local_cmd(tool)
  return not exit_code




def run_local_cmd(cmd):
  proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out, err = proc.communicate()
  exit_code = proc.wait()
  output = out.decode('ascii')
  err = err.decode('ascii')
  if err != '':
    msg = 'COMMAND FAILED\n' + '$ ' + cmd + '\n' + err
    stop(msg)
  return output, exit_code




def stop(msg=None):
  if msg is not None:
    print(msg)
  import sys
  sys.exit()
