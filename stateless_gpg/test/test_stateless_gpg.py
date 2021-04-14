# Imports
import os
import pkgutil




# Relative imports
from ..code.stateless_gpg import gpg




# Shortcuts
join = os.path.join




def test_hello_world():
  data = "hello world\n"
  private_key_file = '../data/test_key_1_private_key.txt'
  private_key_bytes = pkgutil.get_data(__name__, private_key_file)
  private_key = private_key_bytes.decode('ascii')
  signature = gpg.make_signature(private_key, data)
  public_key_file = '../data/test_key_1_public_key.txt'
  public_key_bytes = pkgutil.get_data(__name__, public_key_file)
  public_key = public_key_bytes.decode('ascii')
  result = gpg.verify_signature(public_key, data, signature)
  assert result == True


