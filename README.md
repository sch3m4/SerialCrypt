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

Sample Output
=============

~$ ./crypt.py 
Sending signal to dev
Receiving dev's nonce
    ENCODED: zGUfyFfcVPWXBA1R4NSE5Nz1PbQ2Wld42KgE3cVNlyA=
    ENCRYPTED: cc651fc857dc54f597040d51e0d484e4dcf53db4365a5778d8a804ddc54d9720

Forwarding dev's nonce
    ENCRYPTED: cc651fc857dc54f597040d51e0d484e4dcf53db4365a5778d8a804ddc54d9720
    ENCODED: zGUfyFfcVPWXBA1R4NSE5Nz1PbQ2Wld42KgE3cVNlyA=


Receiving cnonce
    ENCODED: HfJIb8eL6kCj1uafuR9042F59c0=
    ENCRYPTED: 1df2486fc78bea40a3d6e69fb91f74e36179f5cd

Forwarding cnonce
    ENCRYPTED: 1df2486fc78bea40a3d6e69fb91f74e36179f5cd
    ENCODED: HfJIb8eL6kCj1uafuR9042F59c0=


Receiveing RND0 from DEV
    ENCODED: NB8A5Rv+czgagwCJFjEEn4njHBK68UO4Xw/H9wEzV/NGqzEVOcf7xqjGfFyz+OEIlhWt5g==
    ENCRYPTED: 341f00e51bfe73381a8300891631049f89e31c12baf143b85f0fc7f7013357f346ab311539c7fbc6a8c67c5cb3f8e1089615ade6
    HMAC:  46ab311539c7fbc6a8c67c5cb3f8e1089615ade6
    DATA: 341f00e51bfe73381a8300891631049f89e31c12baf143b85f0fc7f7013357f3
    PLAIN: 33031ddb78a422d03ab52cc4c5436d709baae7d330e9b0dcde439c94aa6dc90e

Sending RND1 to DEV

    PLAIN: 169dd83797d8c9c7a0ae7ab08e1ce1181712b4e1d7a185d8d26af52dc6124814
    DATA: 1181c509f482982f809856fd5d6e88f7055b4f205db976bc5326ae4e6d4cd6e9
    HMAC: 4a014d5514249af01f5f64be2fda8669bab05b72
    ENCRYPTED: 1181c509f482982f809856fd5d6e88f7055b4f205db976bc5326ae4e6d4cd6e94a014d5514249af01f5f64be2fda8669bab05b72
    ENCODED: EYHFCfSCmC+AmFb9XW6I9wVbTyBduXa8UyauTm1M1ulKAU1VFCSa8B9fZL4v2oZpurBbcg==


Synchronizing with DEV
Upstream Key: 169dd83797d8c9c7a0ae7ab08e1ce1181712b4e1d7a185d8d26af52dc6124814
Downstream Key: 33031ddb78a422d03ab52cc4c5436d709baae7d330e9b0dcde439c94aa6dc90e
Generating DH Parameters
Sending DH Generator

    PLAIN: 0287123493585390998388541026250001188019
    DATA: 1ec5aae34ef07d1e1116b027cb2c8134318928df
    HMAC: 62e024af9a6476e72d24e7a9af637631887622bf
    ENCRYPTED: 1ec5aae34ef07d1e1116b027cb2c8134318928df62e024af9a6476e72d24e7a9af637631887622bf
    ENCODED: HsWq407wfR4RFrAnyyyBNDGJKN9i4CSvmmR25y0k56mvY3YxiHYivw==


Synchronizing with DEV
Sending DH Prime

    PLAIN: 0211016453868687456684434399545730968537
    DATA: fab2e930e76b56b77db5fe48675784aa06b95553
    HMAC: 46dfc8fc5a2e6dacf282bcd44ad459e816fe2c13
    ENCRYPTED: fab2e930e76b56b77db5fe48675784aa06b9555346dfc8fc5a2e6dacf282bcd44ad459e816fe2c13
    ENCODED: +rLpMOdrVrd9tf5IZ1eEqga5VVNG38j8Wi5trPKCvNRK1FnoFv4sEw==


Receiveing DEV Public Key
    ENCODED: lJPcwo2wGY2JueYYkb9J5wrkop04Dw8uJ630n52CwZwB0se9alHLug==
    ENCRYPTED: 9493dcc28db0198d89b9e61891bf49e70ae4a29d380f0f2e27adf49f9d82c19c01d2c7bd6a51cbba
    HMAC:  380f0f2e27adf49f9d82c19c01d2c7bd6a51cbba
    DATA: 9493dcc28db0198d89b9e61891bf49e70ae4a29d
    PLAIN: 0102274502095803754543432122507539135286

DEV Public Key: 0102274502095803754543432122507539135286
Sending Public Key

    PLAIN: 06443774212846604463920511734970083419
    DATA: a6ad982ef87e30288f1f6cd1b204af9b72e61f
    HMAC: 541cf06a743f80fa21249ee6140da2f277457dbf
    ENCRYPTED: a6ad982ef87e30288f1f6cd1b204af9b72e61f541cf06a743f80fa21249ee6140da2f277457dbf
    ENCODED: pq2YLvh+MCiPH2zRsgSvm3LmH1Qc8Gp0P4D6ISSe5hQNovJ3RX2/


Calculating Session Key
Session Key:  0108400163723685166246565551220771384109
Upstream Session Key: c6a9f019129f20c5a3f2ec025aca937a0d8f049c542bb13b8ac07eeea4d1af6b
Downstream Session Key: e33735f5fde3cbd239e9ba7611951f12813757aeb363843f86e91757c8ae2e71
** Encrypted channel established **
Sending string: "this is my test string"

    PLAIN: 74686973206973206d79207465737420737472696e67
    DATA: f7fc16ad8136f3950a7705d5923244ea5c33511d9004
    HMAC: 8c03a7d31092dd699a4a0ccf95d06c5467be0b92
    ENCRYPTED: f7fc16ad8136f3950a7705d5923244ea5c33511d90048c03a7d31092dd699a4a0ccf95d06c5467be0b92
    ENCODED: 9/wWrYE285UKdwXVkjJE6lwzUR2QBIwDp9MQkt1pmkoMz5XQbFRnvguS


Receiving data...
Expected data: "this is my test string"
    ENCODED: kgnRJeYzSx2MsESpK2Qxh9PqVTHZ6uvIFXseiHVTVDhPH8steahPYfd/
    ENCRYPTED: 9209d125e6334b1d8cb044a92b643187d3ea5531d9eaebc8157b1e88755354384f1fcb2d79a84f61f77f
    HMAC:  ebc8157b1e88755354384f1fcb2d79a84f61f77f
    DATA: 9209d125e6334b1d8cb044a92b643187d3ea5531d9ea
    PLAIN: 74686973206973206d79207465737420737472696e67

Received: "this is my test string"
~$ 
