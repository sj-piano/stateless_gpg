import os
join = os.path.join
import shutil
import uuid
import subprocess




# Notes:
# - Some GPG commands send output to stderr. Use 2>&1 to redirect this output to stdout.




class WrapperClass(object):




	def __init__(self):
		pass




	@staticmethod
	def makeSignature(privateKey, data):
		gpgDirName = createTempDirectory()
		dataDirName = createTempDirectory()
		privateKeyFilePath = join(dataDirName, 'privateKey.txt')
		with open(privateKeyFilePath, 'w') as f:
			f.write(privateKey)
		dataFilePath = join(dataDirName, 'data.txt')
		with open(dataFilePath, 'w') as f:
			f.write(data)
		permissionsCmd = 'chmod 700 {g}'.format(g=gpgDirName)
		runLocalCmd(permissionsCmd)
		importCmd = 'gpg --no-default-keyring --homedir {g} --import {p} 2>&1'.format(g=gpgDirName, p=privateKeyFilePath)
		runLocalCmd(importCmd)
		signatureFilePath = join(dataDirName, 'signature.txt')
		signCmd = 'gpg --no-default-keyring --homedir {g} --output {s} --armor --detach-sign {d}'.format(g=gpgDirName, s=signatureFilePath, d=dataFilePath)
		runLocalCmd(signCmd)
		signature = open(signatureFilePath).read()
		shutil.rmtree(gpgDirName)
		shutil.rmtree(dataDirName)
		return signature




	@staticmethod
	def verifySignature(publicKey, data, signature):
		# Example GPG output: Bad signature
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
		gpgDirName = createTempDirectory()
		dataDirName = createTempDirectory()
		publicKeyFilePath = join(dataDirName, 'publicKey.txt')
		with open(publicKeyFilePath, 'w') as f:
			f.write(publicKey)
		dataFilePath = join(dataDirName, 'data.txt')
		with open(dataFilePath, 'w') as f:
			f.write(data)
		signatureFilePath = join(dataDirName, 'signature.txt')
		with open(signatureFilePath, 'w') as f:
			f.write(signature)
		permissionsCmd = 'chmod 700 {g}'.format(g=gpgDirName)
		runLocalCmd(permissionsCmd)
		importCmd = 'gpg --no-default-keyring --homedir {g} --import {p} 2>&1'.format(g=gpgDirName, p=publicKeyFilePath)
		runLocalCmd(importCmd)
		verifyCmd = 'gpg --no-default-keyring --homedir {g} --status-fd 1 --verify {s} {d} 2>&1'.format(g=gpgDirName, s=signatureFilePath, d=dataFilePath)
		output = runLocalCmd(verifyCmd)
		shutil.rmtree(gpgDirName)
		shutil.rmtree(dataDirName)
		result = False
		for line in output.split('\n'):
			if 'gpg: Good signature from' in line:
				result = True
				break
		return result




def createTempDirectory():
	# start the directory name with a dot so that it's hidden.
	def newDirName():
		randomDigits = str(uuid.uuid4())[-10:]
		return '.stateless_gpg_' + randomDigits
	while True:
		name = newDirName()
		if not os.path.exists(name):
			break
	os.mkdir(name)
	return name


def runLocalCmd(cmd):
	proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate()
	if err != '':
		msg = 'COMMAND FAILED\n' + '$ ' + cmd + '\n' + err
		stop(msg)
	return out


def stop(msg=''):
	raise Exception(msg)


