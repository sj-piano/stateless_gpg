from .pytestImports import *
import os
join = os.path.join


# pytests are run from the top-level 'stateless_gpg' package directory.
dataDirPath = 'stateless_gpg/data'


def test_hello_world():
  data = "hello world\n"
  privateKeyFilePath = join(dataDirPath, 'test_key_1_private_key.txt')
  privateKey = open(privateKeyFilePath).read()
  signature = gpg.makeSignature(privateKey, data)
  publicKeyFilePath = join(dataDirPath, 'test_key_1_public_key.txt')
  publicKey = open(publicKeyFilePath).read()
  result = gpg.verifySignature(publicKey, data, signature)
  assert result == True


