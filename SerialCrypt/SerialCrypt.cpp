#include "SerialCrypt.h"

#define XSWAP(x,y)	(x ^= y ,y = x ^ y , x = x ^ y)

SerialCrypt::SerialCrypt()
{
	init = 0;
}

#ifdef SERIAL_CRYPT_DEBUG
char *SerialCrypt::byteToStr ( uint8_t *data , uint32_t size )
{
	char *ret = (char*)malloc ( (size * 2) + 1 );
	register uint32_t c,m;

	for ( m = c = 0 ; m < size ; m++ , c+=2)
		sprintf(&ret[c],"%02x",data[m]);
	ret[m*2] = 0;

	return ret;
}
#endif

uint8_t nibbleFromChar ( char c )
{
	if ( c >= '0' && c <= '9' ) return c - '0';
	if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
	if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
	return 255;
}

uint8_t *SerialCrypt::strToByte ( char *data , uint32_t size )
{
	uint32_t i = 0 , len = size / 2;
	uint8_t *ret = (uint8_t*)malloc ( size / 2);

	for ( i = 0 ; i < len ; i++ , data += 2)
		ret[i] = (nibbleFromChar(*data)<<4) | nibbleFromChar(*(data+1));
	ret[len] = 0;

	return ret;
}

#ifdef SERIAL_CRYPT_DEBUG
void SerialCrypt::_debugCryptCtxt ( struct rc4_state *ctxt )
{
	if ( debug )
	{
		debug->println("");
		debug->print("SBOX: ");
		char *aux = byteToStr ( ctxt->sbox , 128 );
		debug->println(aux);
		free ( aux );
		aux = byteToStr ( &ctxt->sbox[128] , 128 );
		debug->println(aux);
		free ( aux );
		char tmp[17] = {0};
		sprintf(tmp,"i = %d j = %d" , ctxt->i , ctxt->j );
		debug->println(tmp);
	}
}
#endif

void SerialCrypt::_myInit()
{
    if ( init )
	return;

#ifdef SERIAL_CRYPT_DEBUG
  debug = 0;
#endif

  ok_pin = -1;
  error_pin = -1;
  BigNumber::begin();
  init = 1;
}

void SerialCrypt::SetOKPin ( uint8_t pin )
{
	_myInit();
	ok_pin = (int8_t)pin;
	pinMode ( ok_pin , OUTPUT );
	digitalWrite ( ok_pin , 0 );
}

void SerialCrypt::SetErrorPin ( uint8_t pin )
{
	_myInit();
	error_pin = (int8_t)pin;
	pinMode ( error_pin , OUTPUT );
	digitalWrite ( error_pin , 0 );
}

#ifdef SERIAL_CRYPT_DEBUG
void SerialCrypt::SetSerialDebug ( Stream *ptr )
{
	debug = (Stream*)ptr;
	_myInit();
}
#endif


void SerialCrypt::SetSerial( Stream *s )
{
  _myInit();
  stream = s;
}

void SerialCrypt::begin( BigNumber priv )
{
	poweredOn();
	SendRND();
	RecvRND();
	EstablishDH(priv);
}

void SerialCrypt::invalidHMAC()
{
  if ( ! error_pin < 0 )
	digitalWrite ( error_pin , 245 );

  delay(3000);

  // reset the device
  asm volatile ("jmp 0");
}

void SerialCrypt::correctHMAC()
{
  if ( ! error_pin < 0 )
  {
	digitalWrite ( ok_pin , 245 );
	delay(500);
	digitalWrite ( ok_pin , 0 );
  }
}

void SerialCrypt::poweredOn()
{
	uint8_t i;

  if ( error_pin < 0 && ok_pin < 0 )
	return;

  for ( i = 0 ; i < 3 ; i++ )
  {
    if ( ! error_pin < 0 )
	    digitalWrite ( error_pin , 245 );
    if ( ! ok_pin < 0 )
	    digitalWrite ( ok_pin , 245 );

    delay(500);

    if ( ! error_pin < 0 )
	    digitalWrite ( error_pin , 0 );
    if ( ! ok_pin < 0 )
	    digitalWrite ( ok_pin , 0 );
    delay(200);
  }

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Waked up");
#endif
}

/*
 * Password-Based Key Derivation Function 2 (PKCS #5 v2.0)
 * Source Code From PolarSSL
 */
void SerialCrypt::PBKDF2 ( uint8_t *pass, uint32_t pass_len, uint8_t *salt, uint32_t salt_len,uint8_t *output, uint32_t key_len, uint32_t rounds )
{
	register int ret,j;
	register uint32_t i;
	register uint8_t md1[HMAC_DIGEST_SIZE],work[HMAC_DIGEST_SIZE];
	register size_t use_len;
	register uint8_t *out_p = output;
	register uint8_t counter[4];

	for ( i = 0 ; i < sizeof ( counter ) ; i++ )
		counter[i] = 0;
	counter[3] = 1;

	while (key_len)
	{
		sha1.initHmac(pass,pass_len);
		sha1.write(salt,salt_len);
		sha1.write(counter,4);
		hmac = sha1.resultHmac();
		for ( i = 0 ; i < HMAC_DIGEST_SIZE ; i++ )
			work[i] = md1[i] = hmac[i];

		for ( i = 1 ; i < rounds ; i++ )
		{
			sha1.initHmac(pass,pass_len);
			sha1.write(md1,HMAC_DIGEST_SIZE);
			hmac = sha1.resultHmac();

			for ( j = 0 ; j < HMAC_DIGEST_SIZE ; j++ )
			{
				md1[j] = hmac[j];
				work[j] ^= md1[j];
			}
		}

		use_len = (key_len < HMAC_DIGEST_SIZE ) ? key_len : HMAC_DIGEST_SIZE;
		for ( i = 0 ; i < use_len ; i++ )
			out_p[i] = work[i];

		key_len -= use_len;
		out_p += use_len;

		for ( i = 4 ; i > 0 ; i-- )
			if ( ++counter[i-1] != 0 )
				break;
	}
}

void SerialCrypt::syncWithRandom()
{
  /* sends random data (for synchronization pourposes only) */
  register uint8_t aux[SYNC_LENGTH] = {0};
  register uint8_t i;
  for ( i = 0 ; i < sizeof(aux) ; i++ )
    aux[i] = prng.getRndByte();

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Sync with random bytes");
#endif

    stream->write(aux,sizeof(aux));
}

void SerialCrypt::RC4 ( uint8_t *io , uint32_t len )
{
	RC4 ( &rcvctxt , io , len );
}

void SerialCrypt::RC4 ( struct rc4_state *ctxt , uint8_t *io , uint32_t len )
{
	uint32_t i;

	ctxt->i %= SBOX_LENGTH;
	ctxt->j %= SBOX_LENGTH;
	for ( i = 0 ; i < len ; i++ )
	{
		ctxt->i = (ctxt->i + 1) % SBOX_LENGTH;
		ctxt->j = (ctxt->j + ctxt->sbox[ctxt->i]) % SBOX_LENGTH;
		XSWAP ( ctxt->sbox[ctxt->i] , ctxt->sbox[ctxt->j] );
		io[i] ^= ctxt->sbox[(ctxt->sbox[ctxt->i] + ctxt->sbox[ctxt->j]) % SBOX_LENGTH];
	}
}

void SerialCrypt::SetCryptKey ( uint8_t *key , uint8_t klen )
{
	SetCryptKey ( &sndctxt , key , klen );
	SetCryptKey ( &rcvctxt , key , klen );
}

void SerialCrypt::SetCryptKey ( struct rc4_state *ctxt , uint8_t *key , uint8_t klen )
{
//	klen--;

	/* initialize */
	for ( ctxt->i = 0 ; ctxt->i < SBOX_LENGTH ; ctxt->i++ )
		ctxt->sbox[ctxt->i] = ctxt->i;

	ctxt->i = 0;

	/* key schedule algorithm */
	ctxt->j = 0;
	for ( ctxt->i = 0 ; ctxt->i < SBOX_LENGTH ; ctxt->i++ )
	{
		ctxt->j = (ctxt->j + ctxt->sbox[ctxt->i] + key[ctxt->i % klen]) % SBOX_LENGTH;
		XSWAP ( ctxt->sbox[ctxt->i] , ctxt->sbox[ctxt->j] );
	}
	ctxt->i = ctxt->j = 0;
}

void SerialCrypt::SetHMACKey ( uint8_t *key , uint8_t len )
{
#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Setting HMAC key");
#endif
	hmac_key = key;
	hmac_klen = len;
}

void SerialCrypt::sendCrypt ( uint32_t dlen )
{
	sendCrypt ( &sndctxt , dlen );
}

void SerialCrypt::sendCrypt ( uint8_t *data , uint32_t dlen )
{
	uint32_t i;

	for ( i = 0 ; i < dlen ; i++ )
		buffer[i] = data[i];

	sendCrypt(dlen);
}

void SerialCrypt::send ( uint8_t *data , uint32_t dlen )
{
  dlen = base64_encode ( (char*)b64 , (char*)data , dlen );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("    Encoded: ");
		debug->println((char*)b64);
		debug->println("");
	}
#endif

	stream->write(b64,dlen);
}

void SerialCrypt::sendCrypt ( struct rc4_state *ctxt , uint32_t dlen )
{
  register uint32_t i;

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->println("");
		debug->print("    PLAIN: ");
		char *aux = byteToStr ( buffer , dlen );
		debug->println(aux);
		free ( aux );
	}
#endif

  /* encrypt data */
  RC4 ( ctxt , buffer , dlen );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("    ENCRYPTED: ");
		char *aux = byteToStr ( buffer , dlen );
		debug->println(aux);
		free ( aux );
	}
#endif

  /* generates the HMAC of the ciphertext */
  sha1.initHmac(hmac_key,hmac_klen);
  sha1.write(buffer,dlen);
  hmac = sha1.resultHmac();

  /* concatenate ciphertext and HMAC */
  for ( i = 0 ; i < HMAC_DIGEST_SIZE ; i++ )
    buffer[dlen+i] = hmac[i];
  dlen += HMAC_DIGEST_SIZE;

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("    HMAC: ");
		char *aux = byteToStr ( hmac , HMAC_DIGEST_SIZE );
		debug->println(aux);
		free ( aux );

		debug->print("    CIPHERTEXT: ");
		aux = byteToStr ( buffer , dlen );
		debug->println(aux);
		free ( aux );
	}
#endif

	send ( buffer , dlen );
}


uint32_t SerialCrypt::recvCrypt ()
{
	recvCrypt ( &rcvctxt );
}

uint32_t SerialCrypt::recvCrypt ( uint8_t *data , uint32_t dlen )
{
	register uint32_t i;
	register uint32_t ret = recvCrypt(&rcvctxt);
	for ( i = 0 ; i < ret && i < dlen ; i++ )
		data[i] = buffer[i];
}

uint32_t SerialCrypt::recv ( uint8_t *data )
{
	register uint32_t i;
	register uint8_t cont = 0;

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println ( "" );
#endif

	  while ( ! stream->available() );
	  for ( i = 1 ; i <= BUFFER_LENGTH && ( stream->available() || b64[i-1] != 0 ) ; i++ )
	  {
		while ( ! stream->available() && cont < 3 )
		{
			delay(500);
			cont++;
		}

		if ( cont >= 3 )
			break;
		b64[i-1] = stream->read();
	  }
	  /* buffer is too short but there is data to be readed */
	  while ( stream->available() )
	    stream->read();

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("    Encoded: ");
		debug->println((char*)b64);
		//delay(2000);
	}
#endif

  /* decode Base64 */
  return base64_decode ( (char*)data , (char*)b64 , i - 1 );
}

uint32_t SerialCrypt::recvCrypt ( struct rc4_state *ctxt )
{
	register uint32_t b,i,j;

	i = recv ( buffer );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("    Encrypted: ");
		char *aux = byteToStr ( buffer , i );
		debug->println(aux);
		free ( aux );
		//delay(2000);
	}
#endif

	b = i - HMAC_DIGEST_SIZE;
#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("    HMAC: ");
		char *aux = byteToStr ( &buffer[b] , HMAC_DIGEST_SIZE );
		debug->println(aux);
		free ( aux );
		//delay(3000);
	}
#endif

  /* generate HMAC */
  sha1.initHmac(hmac_key,hmac_klen);
  sha1.write(buffer,b);
  hmac = sha1.resultHmac();

  /* verify HMAC */
  for ( j = b ; j < b + HMAC_DIGEST_SIZE - 1; j++ );
    if ( (buffer[j] ^ hmac[j - b ]) != 0 )
      invalidHMAC();

  correctHMAC();

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("    ENCRYPTED: ");
		char *aux = byteToStr ( buffer , b );
		debug->println(aux);
		free ( aux );
	}
#endif

  /* decrypt data */
  RC4 ( ctxt , buffer, b );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("    PLAIN: ");
		char *aux = byteToStr ( buffer , b );
		debug->println(aux);
		free ( aux );
		debug->println ( "" );
	}
#endif

  return b;
}

uint8_t SerialCrypt::checkuToken()
{
	register uint32_t i;
	uint8_t nonce[RANDOM_LENGTH];
	uint8_t cnonce[RANDOM_LENGTH];

	for ( i = 0 ; i < RANDOM_LENGTH ; i++ )
		nonce[i] = prng.getRndByte();
	send ( nonce , RANDOM_LENGTH );

	PBKDF2 ( nonce , i , hmac_key , hmac_klen , cnonce , RANDOM_LENGTH / 2, PBKDF2_ITERATIONS );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("expected cnonce: ");
		char *aux = byteToStr ( cnonce , RANDOM_LENGTH / 2);
		debug->println(aux);
		free ( aux );
	}
#endif

	i = recv ( nonce );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("received: ");
		char *aux = byteToStr ( nonce , RANDOM_LENGTH / 2);
		debug->println(aux);
		free ( aux );
	}
#endif


	for ( i = 0 ; i < ( RANDOM_LENGTH / 2 ) && (nonce[i] ^ cnonce[i]) == 0 ; i++ );

	return (i < ( RANDOM_LENGTH / 2 ) );
}


void SerialCrypt::SendRND()
{
	register uint32_t i;
#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Waitting for signal");
#endif

	/* wait until signal is received */
	while ( ! stream->available() )
		delay ( 10 );
	stream->read();

#ifdef SERIAL_CRYPT_DEBUG
		if ( debug )
			debug->println("Verifying uToken presence");
#endif

	/* check if uToken is present */
	if ( checkuToken() )
	{
#ifdef SERIAL_CRYPT_DEBUG
		if ( debug )
			debug->println("uToken hijacked!!");
#endif
		invalidHMAC(); // same behaviour (device reset)
	}

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Generating RND0");
#endif

  /* generate RND0 */
  for ( i = 0 ; i < RANDOM_LENGTH ; i++ )
	buffer[i] = rnd[RANDOM_DEV][i] = prng.getRndByte();

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Sending RND0");
#endif

  /* send RND0 */
  sendCrypt ( RANDOM_LENGTH );
}

void SerialCrypt::RecvRND()
{
	register uint32_t i,len;
#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Receiveing RND1");
#endif

  /* recv RND1 */
  len = recvCrypt ();

  for ( i = 0 ; i < len && i < RANDOM_LENGTH ; i++ )
    rnd[RANDOM_CLI][i] = buffer[i];

  syncWithRandom();
}

void SerialCrypt::EstablishDH(BigNumber privKey )
{
   register uint32_t i,len;
   char *aux,*tmp;
   BigNumber pk;

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Receiveing DH Generator");
#endif


#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("Downstream Key: ");
		aux = byteToStr ( rnd[RANDOM_CLI] , RANDOM_LENGTH );
		debug->println(aux);
		free ( aux );
		debug->print("Upstream Key: ");
		aux = byteToStr ( rnd[RANDOM_DEV] , RANDOM_LENGTH );
		debug->println(aux);
		free ( aux );
		debug->println ( "" );
	}
#endif

  /* receive DH Generator */
  SetCryptKey ( &rcvctxt , rnd[RANDOM_CLI] , RANDOM_LENGTH );
  len = recvCrypt();

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Converting DH Generator to BigNumber");
#endif

  /* convert DH generator to BigNumber */
  aux = byteToStr ( buffer , len );
  /* discard zeros */
  tmp = aux;
  if ( *tmp == '0' )
	tmp++;
  g = BigNumber(tmp);
  free ( aux );
#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		aux = g.toString();
		debug->print("Result: ");
		debug->println(aux);
		free(aux);
	}
#endif
  syncWithRandom();

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Receiveing DH Prime");
#endif

  /* receive DH Prime */
  len = recvCrypt ();

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->print("Converting DH Prime to BigNumber: ");
#endif

  /* convert DH prime to BigNumber */
  aux = byteToStr ( buffer , len );
  /* discard zeros */
  tmp = aux;
  if ( *tmp == '0' )
	tmp++;
  p = BigNumber(aux);

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println(tmp);
#endif

  free ( aux );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->print("Calculating device's public key: ");
#endif

  /* calculate public key */
  pk = g.powMod(privKey,p);
  dhtmp = pk.toString();

  char *dh1 = (char*)malloc ( strlen(dhtmp) + 2);
  memset ( dh1 , 0 , strlen(dhtmp) + 2);
  if ( strlen(dhtmp) % 2 > 0 )
	sprintf(dh1,"0%s",dhtmp);
  else
	sprintf(dh1,"%s",dhtmp);
  free ( dhtmp );
  dhtmp = dh1;

  len = strlen(dhtmp) / 2;
  uint8_t *buf = strToByte ( dhtmp , strlen ( dhtmp ) );
  free(dhtmp);
  for ( i = 0 ; i < len ; i++ )
	buffer[i] = buf[i];
  free ( buf );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->println(pk);
		debug->println("Sending device's public key");
	}
#endif

  /* send DH public key */
  SetCryptKey ( &sndctxt,rnd[RANDOM_DEV] , RANDOM_LENGTH );
  sendCrypt ( len );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->println("Receiveing peer's public key");
#endif

  /* receive public key */
  len = recvCrypt ();

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
		debug->print("Converting peer's public key to BigNumber: ");
#endif


  aux = byteToStr ( buffer , len );
  /* discard zeros */
  tmp = aux;
  if ( *tmp == '0' )
	tmp++;
  pk = BigNumber(tmp);
  free ( aux );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		aux = pk.toString();
		debug->println(aux);
		free(aux);
	}
#endif

  /* calculate the initial session key */
  pk = pk.powMod(privKey,p);
  dhtmp = pk.toString();

  dh1 = (char*)malloc ( strlen(dhtmp) + 2);
  memset ( dh1 , 0 , strlen(dhtmp) + 2);
  if ( strlen(dhtmp) % 2 > 0 )
	sprintf(dh1,"0%s",dhtmp);
  else
	sprintf(dh1,"%s",dhtmp);
  free ( dhtmp );
  dhtmp = dh1;

  buf = strToByte ( dhtmp , strlen ( dhtmp ) );
  len = strlen(dhtmp) / 2;
  free ( dhtmp );

  for ( i = 0 ; i < len ; i++ )
	buffer[i] = buf[i];
  free ( buf );

#ifdef SERIAL_CRYPT_DEBUG
	if ( debug )
	{
		debug->print("Session key: ");
		aux = byteToStr ( buffer , len );
		debug->println(aux);
		free(aux);
	}
#endif

  PBKDF2 ( buffer , len, hmac_key , hmac_klen , session_key [ RANDOM_CLI ] , RANDOM_LENGTH , PBKDF2_ITERATIONS );
  PBKDF2 ( buffer , len, hmac_key , hmac_klen, session_key [ RANDOM_DEV ] , RANDOM_LENGTH , PBKDF2_ITERATIONS );

  /* concatenate the initial random with the pbkdf2 */
  for ( i = 0 ; i < RANDOM_LENGTH ; i++ )
  {
    session_key[RANDOM_CLI][i] ^= rnd[RANDOM_CLI][i];
    session_key[RANDOM_DEV][i] ^= rnd[RANDOM_DEV][i];
  }

#ifdef SERIAL_CRYPT_DEBUG
        if ( debug )
        {
                debug->print("Downstream Session Key: ");
                aux = byteToStr ( session_key[RANDOM_CLI] , RANDOM_LENGTH );
		debug->println(aux);
                free ( aux );
                debug->print("Upstream Session Key: ");
                aux = byteToStr ( session_key[RANDOM_DEV] , RANDOM_LENGTH );
		debug->println(aux);
                free ( aux );
		debug->println("Session established");
	}
#endif

  SetCryptKey ( &rcvctxt , session_key[RANDOM_CLI] , RANDOM_LENGTH );
  SetCryptKey ( &sndctxt , session_key[RANDOM_DEV] , RANDOM_LENGTH );

}

