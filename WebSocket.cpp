#include "WebSocket.h"
#include "sha1.h"
#include "base64.h"

WebSocket::WebSocket(uint16_t port, char *supportedProtocol, onOpen_t onOpen, onMessage_t onMessage, onClose_t onClose, onError_t onError) : server(port) {
  this->port = port;
  this->supportedProtocol = strdup(supportedProtocol);
  this->onOpen = onOpen;
  this->onMessage = onMessage;
  this->onClose = onClose;
  this->onError = onError;

  for (int i = 0; i < MAX_SOCK_NUM; i++) {
    status[i] = CLOSED;
  }
}

void WebSocket::begin() {
  server.begin();
}

int WebSocket::available(int &clientNo) {
  char payloadData[WS_MAX_PAYLOAD_LENGTH + 1];
  int payloadLength;
  char requestURI[WS_MAX_LINE_LENGTH];
  int opcode;
  EthernetClient c;
  int retval = WS_ERROR;
  
  clientNo = -1;

  if (c = server.available()) {
    // check for the connection 
    for (int i = 0; i < MAX_SOCK_NUM; i++) {
      if (c == client[i]) { // existing connection
        clientNo = i;
        if (status[i] == OPEN) {
          if (client[clientNo].available()) {
            opcode = readFrame(payloadData, &payloadLength, clientNo);
            switch (opcode) {
              case WS_FRAME_TEXT:
              case WS_FRAME_BINARY:
                if (onMessage) {
                  onMessage(payloadData, payloadLength, clientNo);
                }
                return WS_DATA_RECEIVCED;
              case WS_FRAME_CLOSE :
                if (onClose) {
                  onClose(clientNo);
                }
                sendClose(WS_CLOSE_NORMAL, clientNo);
                client[clientNo].stop();
                return WS_CLOSED;
              default: // got unsupported or unknown message
                if (onError) {
                  onError(clientNo);
                }
                return WS_PROTOCOL_ERROR;
            }
          } else {  // server is available but client is not available
            if (onError) {
              onError(clientNo);
            }
            return WS_STATUS_MISMATCH;
          }
        } else { // status is not OPENl
          if (onError) {
            onError(clientNo);
          }
          return WS_STATUS_MISMATCH;
        }
      }
    }
    
    // New connection.
    for (int i = 0; i < MAX_SOCK_NUM; i++) {
      if (status[i] == CLOSED) {
        clientNo = i;
        client[i] = c;
        if (handshake(requestURI, clientNo) == WS_OK) {
          if (onOpen) {
            onOpen(requestURI, clientNo);
          }
          status[clientNo] = OPEN;
          return WS_CONNECTED;
        } else {
          status[clientNo] = CLOSED;
          return WS_ERROR;
        }
      }
    }
    
    wsAvailableError:
    if (onError) {
      onError(clientNo);
    }
    return retval;
  }
}

int WebSocket::sendText(char *text, int clientNo) {
  return sendPayload((uint8_t *)text, strlen(text), WS_FRAME_TEXT, clientNo);
}

int WebSocket::sendBinary(uint8_t *data, uint8_t dataLength, int clientNo) {
  return sendPayload(data, dataLength, WS_FRAME_BINARY, clientNo);
}

int WebSocket::sendPayload(uint8_t *payLoadData, uint8_t payloadLength, uint8_t opcode, int clientNo) {
  int from, to;
  if (clientNo == -1) {
    from = 0;
    to = MAX_SOCK_NUM;
  } else {
    from = clientNo;
    to = clientNo + 1;
  }
  
  for (int i = from; i < to; i++) {
    if (status[i] == OPEN) {
      if (payloadLength > WS_MAX_PAYLOAD_LENGTH) {
        return WS_LINE_TOO_LONG;
      }

      client[i].write(WS_FRAME_FIN | opcode);
      client[i].write(payloadLength & 0x7f);
      for (int j = 0; j < payloadLength; j++) {
        client[i].write(payLoadData[j]);
      }
    }
  }
  return WS_OK;
}

int WebSocket::sendClose(uint16_t statusCode, int clientNo) {
  int retval = WS_STATUS_MISMATCH;
  
  if (status[clientNo] == OPEN) {
    client[clientNo].write(WS_FRAME_FIN | WS_FRAME_CLOSE);
    client[clientNo].write((uint8_t)(statusCode >> 8));
    client[clientNo].write((uint8_t)(statusCode & 0xff));
    retval = WS_OK;
  }
  
  status[clientNo] = CLOSED;
  return retval;
}

int WebSocket::handshake(char * requestURI, int clientNo) {
  char buffer[WS_MAX_LINE_LENGTH];
  char wsKey[WS_MAX_LINE_LENGTH];
  char charRead;
  int numRead = 0;
  uint8_t headerValidation = 0;
  SHA1Context sha;

  while (readHTMLHeader((uint8_t *)buffer, WS_MAX_LINE_LENGTH, clientNo) > 0) {
    if (strncmp((char *)buffer, "GET", 3) == 0) {
      strtok((char *)buffer, " \t");
      strcpy(requestURI, strtok(NULL, " \t"));
      headerValidation |= WS_HAS_GET;
    } else if (strncasecmp((char *)buffer, "host:", 5) == 0) {
      headerValidation |= WS_HAS_HOST;
    } else if (strncasecmp((char *)buffer, "upgrade:", 8) == 0) {
      strtok((char *)buffer, " \t");
      if (strncasecmp(strtok(NULL, " \t"), "websocket", 9) == 0) {
        headerValidation |= WS_HAS_UPGRADE;
      }
    } else if (strncasecmp((char *)buffer, "connection:", 11) == 0) {
      headerValidation |= WS_HAS_CONNECTION;
    } else if (strncasecmp((char *)buffer, "sec-websocket-protocol:", 23) == 0) {
      headerValidation |= WS_HAS_SUBPROTOCOL;
    } else if (strncasecmp((char *)buffer, "sec-websocket-key:", 18) == 0) {
      strtok((char *)buffer, " \t");
      strcpy((char *)wsKey, strtok(NULL, " \t"));
      headerValidation |= WS_HAS_SEC_WEBSOCKET_KEY;
    } else if (strncasecmp((char *)buffer, "sec-websocket-version:", 22) == 0) {
      strtok((char *)buffer, " \t");
      if (strncasecmp(strtok(NULL, " \t"), "13", 2) == 0) {
        headerValidation |= WS_HAS_SEC_WEBSOCKET_VERSION;
      }
    }
  }

  if (headerValidation == WS_HAS_ALL_HEADERS) {
    strcat((char *)wsKey, WS_GUID);
    SHA1Reset(&sha);
    SHA1Input(&sha, (uint8_t *)wsKey, strlen(wsKey));
    SHA1Result(&sha, (uint8_t *)buffer);
    buffer[20] = 0;

    base64Encode(buffer, wsKey);
    client[clientNo].print("HTTP/1.1 101 Switching Protocols\r\n");
    client[clientNo].print("Upgrade: websocket\r\n");
    client[clientNo].print("Connection: Upgrade\r\n");
    client[clientNo].print("Sec-WebSocket-Accept: ");
    client[clientNo].print(wsKey);
    client[clientNo].print("\r\n");
    if (headerValidation & WS_HAS_SUBPROTOCOL) {
      client[clientNo].print("Sec-WebSocket-Protocol: ");
      client[clientNo].print(supportedProtocol);
      client[clientNo].print("\r\n");
    }
    client[clientNo].print("\r\n");
    return WS_OK;
  } else {
    return WS_ERROR;
  }
}

int WebSocket::readHTMLHeader(uint8_t * buffer, uint8_t bufferLength, int clientNo) {
  int dataRead;
  int numRead = 0;

  while ((dataRead = client[clientNo].read()) != -1) {
    buffer[numRead++] = dataRead;
    if (dataRead == '\n') {
      buffer[numRead - 2] = '\0';
      return WS_OK;
    } else if (numRead > bufferLength) {
      return WS_CLOSE_MESSAGE_TOO_BIG;
    }
  }

  return WS_ERROR;
}

int WebSocket::readFrame(char * payloadData, int * payloadLength, int clientNo) {
  uint8_t data;
  int opcode;
  int mask;
  char maskingKey[4];

  data = client[clientNo].read();
  if (!(data & 0x80)) {
    return WS_NOT_SUPPORTED;
  }
  opcode = data & 0x0f;

  data = client[clientNo].read();
  mask = data & 0x80 ? true : false;
  *payloadLength = data & 0x7f;

  if (*payloadLength > 125) {
    return WS_NOT_SUPPORTED;
  }

  if (mask) {
    for (int i = 0; i < 4; i++) {
      maskingKey[i] = client[clientNo].read();
    }
  }

  for (int i = 0; i < *payloadLength; i++) {
    if (mask) {
      payloadData[i] = client[clientNo].read() ^ maskingKey[i % 4];
    } else {
      payloadData[i] = client[clientNo].read();
    }
  }
  payloadData[*payloadLength] = '\0';

  return opcode;
}

