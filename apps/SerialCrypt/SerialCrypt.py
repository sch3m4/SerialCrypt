#!/usr/bin/env python
#
# Written by Chema Garcia (aka sch3m4)
# Contact: chema@safetybits.net || @sch3m4 || http://safetybits.net
#

import time
import serial
import serial.tools.list_ports
import hmac
from base64 import b64encode , b64decode
from hashlib import sha1
from Crypto import Random
from Crypto.Util.number import getPrime
from passlib.utils.pbkdf2 import pbkdf2

from RC4 import RC4
import Devices

class SerialCrypt:
	# default values
	DEFAULT_BAUDRATE = 9600
	DEFAULT_TIMEOUT = 5
	# variables
	SERIAL_BD = None
	SERIAL_PORT = None
	SERIAL_TIMEOUT = None
	DEVICE_ID = None
	UTOKEN_ID = None
	##########################
	# cryptoraphic constants #
	##########################
	# HMAC key
	HMAC_KEY = None
	# DH Parameters
	DH_PARAM_SIZE = 128
	# HMAC digest size
	HMAC_DIGEST_SIZE = 20
	# RND size
	RND_SIZE = 32
	# PBKDF2 Rounds
	PBKDF2_ROUNDS = 100
	########################
	# cryptographic values #
	########################
	CIPHER_SEND = None	# object to send data
	CIPHER_RECV = None	# object to receive data
	RND_CRYPT0 = None	# dev received random
	RND_CRYPT1 = None	# sent random
	DH_PRIME = None		# prime number
	DH_GENERATOR = None	# generator
	DH_PRIVATE = None	# private key
	DH_PUBLIC = None	# public key
	DH_DEV_PUBLIC = None	# device's public key

	def __init__(self,serialport=None,baudrate=DEFAULT_BAUDRATE,timeout=DEFAULT_TIMEOUT,device_id=Devices.DEVICE_CRYPT_ID,utoken_id=Devices.DEVICE_UTOKEN_ID):
		self.SERIAL_BD = baudrate
		self.SERIAL_PORT = serialport
		self.SERIAL_TIMEOUT = timeout
		self.DEVICE_ID = device_id
		self.UTOKEN_ID = utoken_id

	def setCryptKey(self,stream_key , hmac_key ):
		self.CIPHER_SEND = RC4()
		self.CIPHER_RECV = RC4()
		self.CIPHER_SEND.SetKey( stream_key )
		self.CIPHER_RECV.SetKey( stream_key )
		self.HMAC_KEY = hmac_key

	def __xor__(self,data, key):
	        l = len(key)
        	buff = ''
	        for i in range(0, len(data)):
	                buff += chr(ord(data[i]) ^ ord(key[i % l]))
        	return buff

	def locateDevices(self):
		'''
		Returns the serial port path of the arduino if found, or None if it isn't connected
		'''
		# verify the arduino is connected
		for port in serial.tools.list_ports.comports():
			if port[2][:len(self.DEVICE_ID)] == self.DEVICE_ID:
				self.SERIAL_PORT = port[0]
			elif port[2][:len(self.UTOKEN_ID)] == self.UTOKEN_ID:
				self.SERIAL_UTOKEN = port[0]

		if self.SERIAL_PORT is None or self.SERIAL_UTOKEN is None:
			return None
		return (self.SERIAL_PORT,self.SERIAL_UTOKEN)
#		return (self.SERIAL_PORT,None)

	def connectDEV(self):
		try:
			self.COM_SERIAL = serial.Serial(self.SERIAL_PORT,self.SERIAL_BD,timeout=self.SERIAL_TIMEOUT)
			self.COM_SERIAL.setDTR(False)
			self.COM_SERIAL.setRTS(True)
			self.COM_SERIAL.flushInput()
			self.COM_SERIAL.flushOutput()
			self.COM_SERIAL.setRTS(False)
			self.COM_SERIAL.setDTR(True)
			time.sleep(2)
			self.COM_SERIAL.timeout = 1
			self.COM_SERIAL.read()
			self.COM_SERIAL.timeout = self.SERIAL_TIMEOUT
			return self.COM_SERIAL
		except Exception,e:
			print e
			return None

	def connectUToken(self):
		try:
			self.UTOKEN_SERIAL = serial.Serial(self.SERIAL_UTOKEN,self.SERIAL_BD,timeout=self.SERIAL_TIMEOUT)
			self.UTOKEN_SERIAL.setDTR(False)
			self.UTOKEN_SERIAL.setRTS(True)
			self.UTOKEN_SERIAL.flushInput()
			self.UTOKEN_SERIAL.flushOutput()
			self.UTOKEN_SERIAL.setRTS(False)
			self.UTOKEN_SERIAL.setDTR(True)
			time.sleep(2)
			self.UTOKEN_SERIAL.timeout = 1
			self.UTOKEN_SERIAL.read()
			self.UTOKEN_SERIAL.timeout = self.SERIAL_TIMEOUT
			return self.UTOKEN_SERIAL
		except Exception,e:
			print e
			return None

	def connect(self):
		a = self.connectDEV()
		b = self.connectUToken()

		if a is None or b is None:
			return None
		return (a,b)

	def __genDHParams__(self):
		'''
		Generates DH parameters
		'''
		self.DH_PRIME = getPrime(self.DH_PARAM_SIZE,Random.new().read)
		self.DH_PRIVATE = getPrime(self.DH_PARAM_SIZE,Random.new().read)
		self.DH_GENERATOR = getPrime(self.DH_PARAM_SIZE,Random.new().read)
		self.DH_PUBLIC = pow(self.DH_GENERATOR,self.DH_PRIVATE,self.DH_PRIME)

	def calcHMAC ( self , data ):
		return hmac.new(self.HMAC_KEY,data,sha1).digest()

	def verifyHMAC ( self , data ,  target ):
		if target.encode('hex') == self.calcHMAC(data).encode('hex'):
			return True
		return False

	def syncWithRandom(self,bytes):
		aux = ''
		while not len(str(aux.encode('hex'))) == bytes*2:
			aux += self.COM_SERIAL.read()
		return aux

	def NumtoHex(self,num):
		num = str(num)
		while len(num)%2 != 0:
			num = "0%s" %num
		return num.decode('hex')

	def send(self,serial,data):
		# send it
		print "    ENCRYPTED: %s" % data.encode('hex')
		data = b64encode ( data )
		print "    ENCODED: %s" % data
		serial.write(data + '\x00');
		serial.flushOutput()
		print "\n"

	def sendCrypt(self,text,cobject=None):
		'''
		Calculates HMAC-SHA1 and generates an encrypted ciphertext to send it off the wire
		'''
		if cobject is None:
			cobject = self.CIPHER_SEND

		print ""
		print "    PLAIN: %s" % text.encode('hex')

		# encrypt and calculate HMAC
		cipher = cobject.Crypt(text)
		print "    DATA: %s" % cipher.encode('hex')
		chmac = hmac.new(self.HMAC_KEY,cipher,sha1).digest()
		print "    HMAC: %s" % chmac.encode('hex')
		cipher = cipher + chmac
		self.send ( self.COM_SERIAL , cipher )

	def recv(self,serial):
		buffer = ''
		aux = ''
		while len(str(aux.encode('hex'))) == 0:
			aux = serial.read()
		while len(str(aux.encode('hex'))) > 0:
			buffer += aux
			aux = serial.read()
		serial.flushInput()
		print "    ENCODED: %s" % buffer
		buffer = b64decode ( buffer )
		print "    ENCRYPTED: %s" % buffer.encode('hex')
		return buffer

	def recvCrypt(self,cobject=None):
		buffer = self.recv(self.COM_SERIAL)
		# extract HMAC
		target = buffer[-1*self.HMAC_DIGEST_SIZE:]
		data = buffer[:len(buffer)-self.HMAC_DIGEST_SIZE]
		print "    HMAC:  %s" % target.encode('hex')
		print "    DATA: %s" % data.encode('hex')
		if self.verifyHMAC ( data , target ) is False:
			return None

		# decrypt data
		if cobject is None:
			cobject = self.CIPHER_RECV

		plain = cobject.Crypt(data)
		print "    PLAIN: %s" % plain.encode('hex')
		print ""
		return plain

	def establishCipher(self):
		print "Sending signal to dev"
		self.COM_SERIAL.write ( Random.new().read(1) )

		# receives the nonce
		# -----------------------------------------------------------
		print "Receiving dev's nonce"
		nonce = self.recv(self.COM_SERIAL)
		print ""
		print "Forwarding dev's nonce"
		self.send ( self.UTOKEN_SERIAL , nonce )
		print "Receiving cnonce"
		cnonce = self.recv ( self.UTOKEN_SERIAL )
		print ""
		print "Forwarding cnonce"
		self.send ( self.COM_SERIAL , cnonce )
		# -----------------------------------------------------------


		# -----------------------------------------------------------
		print "Receiveing RND0 from DEV"
		# receives RND0 from arduino: C0 = enc ( RND0 + HMAC ( RND0 , Kb ) , Ka )
		buffer = self.recvCrypt() # we get: RND0 + HMAC ( RND0 , Kb ) , Ka )
		if buffer is None:
			print "Invalid HMAC"
			return False
		# initialize object with the received RND0 to decrypt future received data
		self.RND_CRYPT0 = buffer[:self.RND_SIZE]
		print "Sending RND1 to DEV"
		# send RND1: C1 = enc ( RND1 + HMAC ( RND1 , Kb ) , Ka )
		self.RND_CRYPT1 = Random.new().read(self.RND_SIZE)
		self.sendCrypt ( self.RND_CRYPT1 )
		# -----------------------------------------------------------


		print "Synchronizing with DEV"
		self.syncWithRandom(16)
		# initialize a new object to encrypt future transmissions
		self.CIPHER_RECV.SetKey ( self.RND_CRYPT0 )
		self.CIPHER_SEND.SetKey ( self.RND_CRYPT1 )

		print "Upstream Key: %s" % self.RND_CRYPT1.encode('hex')
		print "Downstream Key: %s" % self.RND_CRYPT0.encode('hex')

		# -----------------------------------------------------------
		print "Generating DH Parameters"
		# generates DH parameters
		self.__genDHParams__()
		print "Sending DH Generator"
		self.sendCrypt ( self.NumtoHex(self.DH_GENERATOR) )
		# -----------------------------------------------------------


		print "Synchronizing with DEV"
		self.syncWithRandom(16)


		# -----------------------------------------------------------
		print "Sending DH Prime"
		self.sendCrypt ( self.NumtoHex(self.DH_PRIME) )
		print "Receiveing DEV Public Key"
		# receives DEV public key: C3 = enc ( PK0 + HMAC ( PK0 , Kb ) , RND0 )
		buffer = self.recvCrypt() # we get: PK0 + HMAC ( PK0 , Kb )
		if buffer is None:
			print "Invalid HMAC"
			return False
		self.DH_DEV_PUBLIC = buffer
		print "DEV Public Key: %s" % self.DH_DEV_PUBLIC.encode('hex')
		# -----------------------------------------------------------


		# -----------------------------------------------------------
		print "Sending Public Key"
		self.sendCrypt ( self.NumtoHex ( self.DH_PUBLIC ) )
		# -----------------------------------------------------------


		# -----------------------------------------------------------
		print "Calculating Session Key"
		# calculate session key
		self.SESSION_KEY = self.NumtoHex ( pow(long( self.DH_DEV_PUBLIC.encode('hex') ), self.DH_PRIVATE , self.DH_PRIME) )
		print "Session Key: " , self.SESSION_KEY.encode('hex')
		self.SESSION_KEY = pbkdf2 ( self.SESSION_KEY , self.HMAC_KEY , self.PBKDF2_ROUNDS , self.RND_SIZE , 'hmac-sha1' )
		upstream = self.__xor__ ( self.SESSION_KEY , self.RND_CRYPT1 )
		downstream = self.__xor__ ( self.SESSION_KEY , self.RND_CRYPT0 )
		self.CIPHER_SEND.SetKey ( upstream )
		self.CIPHER_RECV.SetKey ( downstream )
		# -----------------------------------------------------------
		print "Upstream Session Key: %s" % upstream.encode('hex')
		print "Downstream Session Key: %s" % downstream.encode('hex')
		return True


if __name__ == "__main__":
	print "This is script is a Python module"
