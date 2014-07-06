#ifndef __SERIAL_CRYPT_H__
# define __SERIAL_CRYPT_H__

#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

#include <SoftwareSerial.h>
#include "sha1.h"
#include "aes256.h"
#include "base64.h"
#include "BigNumber.h"
#include "pRNG.h"

/* cryptographic constants */
#define HMAC_DIGEST_SIZE  	20
#define PBKDF2_ITERATIONS	100
#define SESSION_KEY_LENGTH	32
#define SBOX_LENGTH		256
/* random numbers indexes */
#define RANDOM_DEV	0
#define RANDOM_CLI	1
#define RANDOM_NUM	2
/* random length */
#define RANDOM_LENGTH   32
/* buffer length (due to uint8_t index, the buffer is limited to 256 bytes length) */
//#define BUFFER_LENGTH  5*16
#define BUFFER_LENGTH  257

/* sync. bytes */
#define SYNC_LENGTH	16

struct rc4_state
{
	uint8_t sbox[SBOX_LENGTH];
	uint32_t i;
	uint32_t j;
};

#ifdef __cplusplus
extern "C" {
#endif

#define SERIAL_CRYPT_DEBUG

class SerialCrypt
{
	public:
		SerialCrypt();
		void SetSerial ( Stream * );
		void RC4 ( uint8_t * , uint32_t );
		void SetCryptKey ( uint8_t * , uint8_t );
		void SetHMACKey ( uint8_t * , uint8_t );
		void sendCrypt ( uint32_t );
		void sendCrypt ( uint8_t * , uint32_t );
		uint32_t recvCrypt ();
		uint32_t recvCrypt ( uint8_t * , uint32_t );
		void SetOKPin ( uint8_t );
		void SetErrorPin ( uint8_t );
		void begin ( BigNumber );
#ifdef SERIAL_CRYPT_DEBUG
		void SetSerialDebug ( Stream * );
#endif

	private:
		/* methods */
		void SendRND();
		void RecvRND();
		void _debugCryptCtxt ( struct rc4_state * );
		void sendCrypt ( struct rc4_state * , uint32_t );
		uint32_t recvCrypt ( struct rc4_state * );
		void EstablishDH( BigNumber );
		void SetCryptKey ( struct rc4_state *, uint8_t * , uint8_t );
		uint8_t checkuToken();
		uint32_t recv ( uint8_t* );
		void send ( uint8_t * , uint32_t );
		void RC4 ( struct rc4_state *, uint8_t * , uint32_t );
		void PBKDF2 ( uint8_t *, uint32_t , uint8_t *, uint32_t ,uint8_t *, uint32_t , uint32_t );
		/* serial stream */
		Stream *stream;
		/* serial debug */
#ifdef SERIAL_CRYPT_DEBUG
		Stream	*debug;
#endif
		/* RC4 context */
		struct rc4_state rcvctxt;
		struct rc4_state sndctxt;
		/* session key */
		uint8_t session_key[RANDOM_NUM][RANDOM_LENGTH];
		/* Randoms */
		uint8_t rnd[RANDOM_NUM][RANDOM_LENGTH];
		/* HMAC */
		Sha1Class sha1;
		uint8_t *hmac_key;
		uint16_t hmac_klen;
		uint8_t *hmac;
		/* pseudorandom number generator */
		pRNG prng;
		/* bignumbers for DH key exchange */
		BigNumber p;
		BigNumber g;
		/* I/O buffer */
		uint8_t b64[BUFFER_LENGTH];
		uint8_t buffer[BUFFER_LENGTH];
		/* auxiliary variables */
		char *dhtmp;
		/* auxiliary functions */
		void _myInit();
		void invalidHMAC();
		void correctHMAC();
		void poweredOn();
		void syncWithRandom();
		char *byteToStr ( uint8_t * , uint32_t );
		uint8_t *strToByte ( char * , uint32_t );
		/* led indicators */
		int8_t ok_pin;
		int8_t error_pin;
		/* initialized? */
		uint8_t init;
};

#ifdef __cplusplus
}
#endif

#endif /* __SERIAL_CRYPT_H__ */
