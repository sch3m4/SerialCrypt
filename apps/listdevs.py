#!/usr/bin/env python
#
# Written by Chema Garcia (aka sch3m4)
# Contact: chema@safetybits.net || http://safetybits.net || @sch3m4
#

import serial.tools.list_ports

def main():
	for port in serial.tools.list_ports.comports():
		if len(port[2]) > 3:
			print port

if __name__ == "__main__":
	main()
