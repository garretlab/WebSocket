#include <SPI.h>
#include <Ethernet.h>
#include "WebSocket.h"

WebSocket wsServer(80, connectHandler, messageHandler, closeHandler, errorHandler);

void connectHandler(char *requestURI) {
  Serial.println(requestURI);
  Serial.println("connected");
}

void messageHandler(char *message, int payloadLength) {
  Serial.print("length = "); 
  Serial.print(payloadLength);
  Serial.print(", message = ");
  Serial.println(message);
}

void closeHandler() {
  Serial.println("closed");
}

void errorHandler() {
  Serial.println("error");
}

void sendAnalogData() {
  static unsigned long lastTime = 0;
  unsigned long currentTime;
  
  char buffer[WS_MAX_PAYLOAD_LENGTH];
  
  currentTime = millis();
  if ((currentTime - lastTime) > 3000) {
    sprintf(buffer, "Value = %d", analogRead(0));
    Serial.println(buffer);
    if (wsServer.status == OPEN) {
      wsServer.sendText(buffer);
    }
    lastTime = currentTime;
  }
}

void setup() {
  byte macAddress[] = {0x90, 0xa2, 0xda, 0x0d, 0xd2, 0xef};
  byte ipAddress[] = {192, 168, 11, 200};

  Serial.begin(9600);
  Ethernet.begin(macAddress, ipAddress);
  Serial.print("Server is at ");
  Serial.println(Ethernet.localIP());
  
  wsServer.begin();
}

void loop() {
  // put your main code here, to run repeatedly:
  wsServer.available();
  
  sendAnalogData();
}
