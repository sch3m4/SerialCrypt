#!/usr/bin/env python
#
# Written by Chema Garcia (aka sch3m4)
# Contact: chema@safetybits.net || http://safetybits.net || @sch3m4
#

import sys
import time
import serial
import serial.tools.list_ports

from SerialCrypt import Devices

# variables
SERIAL_BD = 9600
SERIAL_PORT = None
SERIAL_TIMEOUT = 5

# verify the arduino is connected
for port in serial.tools.list_ports.comports():
	if port[2][:len(Devices.DEVICE_DEBUG_ID)] == Devices.DEVICE_DEBUG_ID:
		SERIAL_PORT = port[0]
		break

try:
	COM_SERIAL = serial.Serial(SERIAL_PORT,SERIAL_BD,timeout=SERIAL_TIMEOUT)
	COM_SERIAL.setDTR(False)
	COM_SERIAL.setRTS(True)
	COM_SERIAL.flushInput()
	COM_SERIAL.flushOutput()
	COM_SERIAL.setRTS(False)
	COM_SERIAL.setDTR(True)
except Exception,e:
	print e

try:
	while True:
		byte = COM_SERIAL.read()
		if len(byte) > 0:
			sys.stdout.write(byte)
except:
	pass
