#!/usr/bin/env python
#
# Written by Chema Garcia (aka sch3m4)
# Contact: chema@safetybits.net || http://safetybits.net || @sch3m4
#

import serial.tools.list_ports
from SerialCrypt import Devices

def locateDevice(devid):
	'''
	Returns the serial port path of the arduino if found, or None if it isn't connected
	'''
	retval = None
	for port in serial.tools.list_ports.comports():
		if port[2][:len(devid)] == devid:
			retval = port[0]
			break

	return retval


def main():
	print "HSM Device:    %s" % locateDevice ( Devices.DEVICE_CRYPT_ID )
	print "uToken Device: %s" % locateDevice ( Devices.DEVICE_UTOKEN_ID )
	print "Debug Device:  %s" % locateDevice ( Devices.DEVICE_DEBUG_ID )

if __name__ == "__main__":
	main()
