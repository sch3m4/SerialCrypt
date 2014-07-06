#!/usr/bin/env python
#
# Written by Chema Garcia (aka sch3m4)
# Contact: chema@safetybits.net || http://safetybits.net || @sch3m4
#

import sys
import time
from SerialCrypt import SerialCrypt

def main():
	scrypt = SerialCrypt()
	scrypt.setCryptKey ( "mysecretrc4key" , "thehmacsecret" )

	if scrypt.locateDevices() is None:
		print "Cannot locate device"
		sys.exit(-1)

	if scrypt.connect() is None:
		print "Cannot connect to device"
		sys.exit(-2)

	if scrypt.establishCipher() is None:
		print "Cannot establish the encrypted communication"
		sys.exit(-3)

	time.sleep(5)
	print "** Encrypted channel established **"

	test_string = 'this is my test string'
	print "Sending string: \"%s\"" % test_string
	scrypt.sendCrypt ( test_string )
	print "Receiving data..."
	print "Expected data: \"%s\"" % test_string
	recv = scrypt.recvCrypt ()
	print "Received: \"%s\"" % recv


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		pass
