#include <SoftwareSerial.h>
#include <SerialCrypt.h>

SerialCrypt scrypt;

#define OK_PIN     11
#define ERROR_PIN  9

uint8_t rc4_key[] =  "mysecretrc4key";
uint8_t hmac_key[] = "thehmacsecret";
uint8_t len;

void setup()
{
  Serial.begin(9600);
  Serial1.begin(9600);

  while ( !Serial );
  while ( !Serial1 );

  scrypt.SetOKPin(OK_PIN);
  scrypt.SetErrorPin(ERROR_PIN);
  scrypt.SetSerial ( &Serial );
  scrypt.SetSerialDebug ( &Serial1 );
  scrypt.SetCryptKey ( rc4_key , 14 );
  scrypt.SetHMACKey ( hmac_key , 13 );
  scrypt.begin ( BigNumber ( "104683" ) );
}

void loop()
{
  len = scrypt.recvCrypt();
  scrypt.sendCrypt(len);
  delay(100);
}

