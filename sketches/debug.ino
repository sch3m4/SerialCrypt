uint8_t data;

void setup()
{
  Serial.begin(9600);
  Serial1.begin(9600);
  
  while ( !Serial );
  while ( !Serial1 );
  
  Serial.println ( "************************************" );
  Serial.println ( "*         Arduino Debugger         *" );
  Serial.println ( "************************************" );
  Serial.println ( "" );
}

void loop()
{
    while ( Serial1.available() )
    {
        data = Serial1.read();
        Serial.write(data);
    }
}
