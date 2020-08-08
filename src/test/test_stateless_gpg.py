from .pytestImports import *


# pytests are run from the main 'stateless-gpg-python2' package directory.
dataDirPath = 'src/data'


def test_sign():
	data = "hello world"
