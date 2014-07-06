#!/usr/bin/env python
#
# Written by Chema Garcia (aka sch3m4)
# Contact: chema@safetybits.net || @sch3m4 || http://safetybits.net
#

class RC4:
	def __init__(self):
		self.SBOX_LENGTH = 256
		self.sbox = range(self.SBOX_LENGTH)
		self.i = self.j = 0

	def SetKey ( self , key ):
		self.__init__()
		j = 0
		for i in range(self.SBOX_LENGTH):
			j = (j + self.sbox[i] + ord ( key[i % len(key)] ) ) % self.SBOX_LENGTH
			self.sbox[i], self.sbox[j] = self.sbox[j], self.sbox[i]
		self.i = self.j = 0

	def Crypt ( self , data ):
		out = []
		self.i %= self.SBOX_LENGTH
		self.j %= self.SBOX_LENGTH
		for char in data:
			self.i = (self.i + 1) % self.SBOX_LENGTH
			self.j = (self.j + self.sbox[self.i]) % self.SBOX_LENGTH
			self.sbox[self.i],self.sbox[self.j] = self.sbox[self.j] , self.sbox[self.i]		
			out.append(chr(ord(char) ^ self.sbox[(self.sbox[self.i] + self.sbox[self.j]) % self.SBOX_LENGTH]))
		return ''.join(out)


if __name__ == "__main__":
	print "This is not a python program but a module"
