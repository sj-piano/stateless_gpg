from ..code.stateless_gpg import gpg
import os
import pkgutil
join = os.path.join




def test_hello_world():
  data = "hello world\n"
  privateKeyFilePath = '../data/test_key_1_private_key.txt'
  privateKey = pkgutil.get_data(__name__, privateKeyFilePath)
  signature = gpg.makeSignature(privateKey, data)
  publicKeyFilePath = '../data/test_key_1_public_key.txt'
  publicKey = pkgutil.get_data(__name__, publicKeyFilePath)
  result = gpg.verifySignature(publicKey, data, signature)
  assert result == True


