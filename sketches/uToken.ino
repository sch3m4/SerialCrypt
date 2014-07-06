#include <sha1.h>


Sha1Class Sha1;
uint8_t hmacKey1[]="thehmacsecret";

#define BUFFER_LENGTH 256
#define OUTPUT_LENGTH  20
#define HMAC_DIGEST_SIZE 20

uint8_t buffer[BUFFER_LENGTH] = {0};
uint8_t b64[BUFFER_LENGTH] = {0};

const char b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


int b64_enc_len(int plainLen) {
	int n = plainLen;
	return (n + 2 - ((n + 2) % 3)) / 3 * 4;
}

int b64_dec_len(char * input, int inputLen) {
	int i = 0;
	int numEq = 0;
	for(i = inputLen - 1; input[i] == '='; i--) {
		numEq++;
	}

	return ((6 * inputLen) / 8) - numEq;
}

inline void a3_to_a4(unsigned char * a4, unsigned char * a3) {
	a4[0] = (a3[0] & 0xfc) >> 2;
	a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
	a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
	a4[3] = (a3[2] & 0x3f);
}

inline void a4_to_a3(unsigned char * a3, unsigned char * a4) {
	a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
	a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
	a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
}

inline unsigned char b64_lookup(char c) {
	if(c >='A' && c <='Z') return c - 'A';
	if(c >='a' && c <='z') return c - 71;
	if(c >='0' && c <='9') return c + 4;
	if(c == '+') return 62;
	if(c == '/') return 63;
	return -1;
}

int b64_encode(char *output, char *input, int inputLen) {
	int i = 0, j = 0;
	int encLen = 0;
	unsigned char a3[3];
	unsigned char a4[4];

	while(inputLen--) {
		a3[i++] = *(input++);
		if(i == 3) {
			a3_to_a4(a4, a3);

			for(i = 0; i < 4; i++) {
				output[encLen++] = b64_alphabet[a4[i]];
			}

			i = 0;
		}
	}

	if(i) {
		for(j = i; j < 3; j++) {
			a3[j] = '\0';
		}

		a3_to_a4(a4, a3);

		for(j = 0; j < i + 1; j++) {
			output[encLen++] = b64_alphabet[a4[j]];
		}

		while((i++ < 3)) {
			output[encLen++] = '=';
		}
	}
	output[encLen] = '\0';
	return encLen;
}

int b64_decode(char * output, char * input, int inputLen) {
	int i = 0, j = 0;
	int decLen = 0;
	unsigned char a3[3];
	unsigned char a4[4];


	while (inputLen--) {
		if(*input == '=') {
			break;
		}

		a4[i++] = *(input++);
		if (i == 4) {
			for (i = 0; i <4; i++) {
				a4[i] = b64_lookup(a4[i]);
			}

			a4_to_a3(a3,a4);

			for (i = 0; i < 3; i++) {
				output[decLen++] = a3[i];
			}
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++) {
			a4[j] = '\0';
		}

		for (j = 0; j <4; j++) {
			a4[j] = b64_lookup(a4[j]);
		}

		a4_to_a3(a3,a4);

		for (j = 0; j < i - 1; j++) {
			output[decLen++] = a3[j];
		}
	}
	output[decLen] = '\0';
	return decLen;
}

void pbkdf2 ( uint8_t *pass, uint32_t pass_len, uint8_t *salt, uint32_t salt_len,uint8_t *output, uint32_t key_len, uint32_t rounds)
{
	register int ret,j;
	register uint32_t i;
	register uint8_t md1[HMAC_DIGEST_SIZE],work[HMAC_DIGEST_SIZE];
	register size_t use_len;
	register uint8_t *out_p = output;
	register uint8_t counter[4];
        register uint8_t *hmac;

	for ( i = 0 ; i < sizeof ( counter ) ; i++ )
		counter[i] = 0;
	counter[3] = 1;

	while (key_len)
	{
		Sha1.initHmac(pass,pass_len);
		Sha1.write(salt,salt_len);
		Sha1.write(counter,4);
		hmac = Sha1.resultHmac();
		for ( i = 0 ; i < HMAC_DIGEST_SIZE ; i++ )
			work[i] = md1[i] = hmac[i];

		for ( i = 1 ; i < rounds ; i++ )
		{
			Sha1.initHmac(pass,pass_len);
			Sha1.write(md1,HMAC_DIGEST_SIZE);
			hmac = Sha1.resultHmac();
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


uint32_t readInput()
{
  register uint32_t i;
  register uint8_t cont = 0;
  
      while ( ! Serial.available() );
      for ( i = 1 ; i <= BUFFER_LENGTH && ( Serial.available() || b64[i-1] != 0 ) ; i++ )
      {
        while ( ! Serial.available() && cont < 3 )
                {
                        delay(500);
                        cont++;
                }

                if ( cont >= 3 )
                        break;
                b64[i-1] = Serial.read();
          }
          /* buffer is too short but there is data to be readed */
          while ( Serial.available() )
            Serial.read();

  /* decode Base64 */
  return b64_decode ( (char*)buffer , (char*)b64 , i - 1 );
}

void setup()
{
  Serial.begin(115200);
  while ( !Serial );
}

void loop()
{
  uint32_t len = readInput();

  pbkdf2 ( buffer , len , hmacKey1 , 13 , b64, OUTPUT_LENGTH , 100 );
  len = b64_encode ( (char*)buffer , (char*)b64 , OUTPUT_LENGTH );
  Serial.write ( buffer , len );
  
  delay(1000);
}
