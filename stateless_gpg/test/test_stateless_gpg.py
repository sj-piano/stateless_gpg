# Imports
import os
import pkgutil




# Relative imports
from ..code.stateless_gpg import gpg




# Shortcuts
join = os.path.join




def test_hello_world():
  data = "hello world\n"
  privateKeyFilePath = '../data/test_key_1_private_key.txt'
  privateKeyBytes = pkgutil.get_data(__name__, privateKeyFilePath)
  privateKey = privateKeyBytes.decode('ascii')
  signature = gpg.makeSignature(privateKey, data)
  publicKeyFilePath = '../data/test_key_1_public_key.txt'
  publicKeyBytes = pkgutil.get_data(__name__, publicKeyFilePath)
  publicKey = publicKeyBytes.decode('ascii')
  result = gpg.verifySignature(publicKey, data, signature)
  assert result == True


