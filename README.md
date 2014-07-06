SerialCrypt
===========

PoC / Arduino library to encrypt serial communications

Devices
=======

This source code uses an Arduino Mega to establish an encrypted communication using RC4,HMAC-SHA1,PBKDF2 and Diffie-Hellman Key Exchange.

Second Factor
=============

Before negotiating the session key and first of all, the device verifies the existence of another device (called uToken) by doing a challenge-response authentication with PBKDF2.

Stability
=========

This code is not so stable as it ought to be, however you can use it as starting point for your future projects as well as source code repository.

Third Party Libraries
=====================

This library uses the following third party libraries:
	- Base64
	- pRNG
	- BigNumber
	- Sha1 (Cryptosuite)
