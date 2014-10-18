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

int WebSocket::available(int *clientId) {
  char payloadData[WS_MAX_PAYLOAD_LENGTH + 1];
  int payloadLength;
  char requestURI[WS_MAX_LINE_LENGTH];
  int opcode;
  EthernetClient c;
  int retval = WS_ERROR;
  
  *clientId = -1;

  if (c = server.available()) {
    // check for the connection 
    for (int i = 0; i < MAX_SOCK_NUM; i++) {
      if (c == client[i]) { // existing connection
        *clientId = i;
        if (status[i] == OPEN) {
          if (client[*clientId].available()) {
            opcode = readFrame(payloadData, &payloadLength, *clientId);
            switch (opcode) {
              case WS_FRAME_TEXT:
              case WS_FRAME_BINARY:
                if (onMessage) {
                  onMessage(payloadData, payloadLength, *clientId);
                }
                return WS_DATA_RECEIVCED;
              case WS_FRAME_CLOSE :
                if (onClose) {
                  onClose(*clientId);
                }
                sendClose(WS_CLOSE_NORMAL, *clientId);
                client[*clientId].stop();
                return WS_CLOSED;
              default: // got unsupported or unknown message
                retval = WS_PROTOCOL_ERROR;
                goto wsAvailableError;
            }
          } else {  // server is available but client is not available
            retval = WS_STATUS_MISMATCH;
            goto wsAvailableError;
          }
        } else { // status is not OPENl
          retval = WS_STATUS_MISMATCH;
          goto wsAvailableError;
        }
      }
    }
    
    // New connection.
    for (int i = 0; i < MAX_SOCK_NUM; i++) {
      if (status[i] == CLOSED) {
        *clientId = i;
        client[i] = c;
        if (handshake(requestURI, *clientId) == WS_OK) {
          if (onOpen) {
            onOpen(requestURI, *clientId);
          }
          status[*clientId] = OPEN;
          return WS_CONNECTED;
        } else {
          status[*clientId] = CLOSED;
          return WS_ERROR;
        }
      }
    }
    
    wsAvailableError:
    if (onError) {
      onError(*clientId);
    }
    return retval;
  }
}

int WebSocket::sendText(char *text, int clientId) {
  return sendPayload((uint8_t *)text, strlen(text), WS_FRAME_TEXT, clientId);
}

int WebSocket::sendBinary(uint8_t *data, uint8_t dataLength, int clientId) {
  return sendPayload(data, dataLength, WS_FRAME_BINARY, clientId);
}

int WebSocket::sendPayload(uint8_t *payLoadData, uint8_t payloadLength, uint8_t opcode, int clientId) {
  if (status[clientId] == OPEN) {
    if (payloadLength > WS_MAX_PAYLOAD_LENGTH) {
      return WS_LINE_TOO_LONG;
    }

    client[clientId].write(WS_FRAME_FIN | opcode);
    client[clientId].write(payloadLength & 0x7f);

    for (int i = 0; i < payloadLength; i++) {
      client[clientId].write(payLoadData[i]);
    }
    return WS_OK;
  } else {
    return WS_STATUS_MISMATCH;
  }
}

int WebSocket::sendClose(uint16_t statusCode, int clientId) {
  if (status[clientId] == OPEN) {
    client[clientId].write(WS_FRAME_FIN | WS_FRAME_CLOSE);
    client[clientId].write((uint8_t)(statusCode >> 8));
    client[clientId].write((uint8_t)(statusCode & 0xff));
    status[clientId] = CLOSED;
    return WS_OK;
  } else {
    return WS_STATUS_MISMATCH;
  }
}

int WebSocket::handshake(char * requestURI, int clientId) {
  char buffer[WS_MAX_LINE_LENGTH];
  char wsKey[WS_MAX_LINE_LENGTH];
  char charRead;
  int numRead = 0;
  uint8_t headerValidation = 0;
  SHA1Context sha;

  while (readHTMLHeader((uint8_t *)buffer, WS_MAX_LINE_LENGTH, clientId) > 0) {
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
    client[clientId].print("HTTP/1.1 101 Switching Protocols\r\n");
    client[clientId].print("Upgrade: websocket\r\n");
    client[clientId].print("Connection: Upgrade\r\n");
    client[clientId].print("Sec-WebSocket-Accept: ");
    client[clientId].print(wsKey);
    client[clientId].print("\r\n");
    if (headerValidation & WS_HAS_SUBPROTOCOL) {
      client[clientId].print("Sec-WebSocket-Protocol: ");
      client[clientId].print(supportedProtocol);
      client[clientId].print("\r\n");
    }
    client[clientId].print("\r\n");
    return WS_OK;
  } else {
    return WS_ERROR;
  }
}

int WebSocket::readHTMLHeader(uint8_t * buffer, uint8_t bufferLength, int clientId) {
  int dataRead;
  int numRead = 0;

  while ((dataRead = client[clientId].read()) != -1) {
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

int WebSocket::readFrame(char * payloadData, int * payloadLength, int clientId) {
  uint8_t data;
  int opcode;
  int mask;
  char maskingKey[4];

  data = client[clientId].read();
  if (!(data & 0x80)) {
    return WS_NOT_SUPPORTED;
  }
  opcode = data & 0x0f;

  data = client[clientId].read();
  mask = data & 0x80 ? true : false;
  *payloadLength = data & 0x7f;

  if (*payloadLength > 125) {
    return WS_NOT_SUPPORTED;
  }

  if (mask) {
    for (int i = 0; i < 4; i++) {
      maskingKey[i] = client[clientId].read();
    }
  }

  for (int i = 0; i < *payloadLength; i++) {
    if (mask) {
      payloadData[i] = client[clientId].read() ^ maskingKey[i % 4];
    } else {
      payloadData[i] = client[clientId].read();
    }
  }
  payloadData[*payloadLength] = '\0';

  return opcode;
}

