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
  status = CLOSED;
}

void WebSocket::begin() {
  server.begin();
}

int WebSocket::available() {
  char payloadData[WS_MAX_PAYLOAD_LENGTH + 1];
  int payloadLength;
  char requestURI[WS_MAX_LINE_LENGTH];
  int opcode;
  
  switch (status) {
  case CLOSED:
    if (client = server.available()) {
      if (handshake(requestURI) == WS_OK) {
        if (onOpen) {
          onOpen(requestURI);
        }
        return WS_CONNECTED;
      } else {
        return WS_ERROR;
      }
    } else {
      return WS_NO_CLIENT;
    }
    break;
  case OPEN:
    if (client.available()) {
      opcode = readFrame(payloadData, &payloadLength);
      switch (opcode) {
      case WS_FRAME_TEXT:
        if (onMessage) {
          onMessage(payloadData, payloadLength);
        }
        return WS_DATA_RECEIVCED;
      case WS_FRAME_CLOSE :
        if (onClose) {
          onClose();
        }
        sendClose(WS_CLOSE_NORMAL);
        client.stop();
        return WS_CLOSED;
      default:
        if (onError) {
          onError();
        }
        return WS_PROTOCOL_ERROR;
      }
    } else {
        return WS_NO_DATA;
    }
    break;
  }
  return WS_ERROR;
}

int WebSocket::sendText(char *text) {
  uint8_t payloadLength = strlen(text);
  
  if (status == OPEN) {
    if (payloadLength > WS_MAX_PAYLOAD_LENGTH) {
      return WS_LINE_TOO_LONG;
    }
    
    client.write(0x81);
    client.write(payloadLength & 0x7f);
    for (int i = 0; i < payloadLength; i++) {
      client.write(text[i]);
    }
    return WS_OK;
  } else {
    return WS_STATUS_MISMATCH;
  }
}

int WebSocket::sendClose(uint16_t statusCode) {
  if (status == OPEN) {
    client.write(0x88);
    client.write((uint8_t)(statusCode >> 8));
    client.write((uint8_t)(statusCode & 0xff));
    status = CLOSED;
    return WS_OK;
  } else {
    return WS_STATUS_MISMATCH;
  }
}

int WebSocket::handshake(char *requestURI) {
  char buffer[WS_MAX_LINE_LENGTH];
  char wsKey[WS_MAX_LINE_LENGTH];
  char charRead;
  int numRead = 0;
  uint8_t headerValidation = 0;
  SHA1Context sha;

  while (readHTMLHeader((uint8_t *)buffer, WS_MAX_LINE_LENGTH) > 0) {
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
    client.print("HTTP/1.1 101 Switching Protocols\r\n");
    client.print("Upgrade: websocket\r\n");
    client.print("Connection: Upgrade\r\n");
    client.print("Sec-WebSocket-Accept: ");
    client.print(wsKey);
    client.print("\r\n");
    client.print("Sec-WebSocket-Protocol: ");
    client.print(supportedProtocol);
    client.print("\r\n");
    client.print("\r\n");

    status = OPEN;
    return WS_OK;
  } else {
    status = CLOSED;
    return WS_ERROR;
  }
}

int WebSocket::readHTMLHeader(uint8_t *buffer, uint8_t bufferLength) {
  int dataRead;
  int numRead = 0;

  while ((dataRead = client.read()) != -1) {
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

int WebSocket::readFrame(char *payloadData, int *payloadLength) {
  uint8_t data;
  int opcode;
  int mask;
  char maskingKey[4];

  data = client.read();
  if (!(data & 0x80)) {
    return WS_NOT_SUPPORTED;
  }
  opcode = data & 0x0f;

  data = client.read();
  mask = data & 0x80 ? true : false;
  *payloadLength = data & 0x7f;

  if (*payloadLength > 125) {
    return WS_NOT_SUPPORTED;
  }

  if (mask) {
    for (int i = 0; i < 4; i++) {
      maskingKey[i] = client.read();
    }
  }

  for (int i = 0; i < *payloadLength; i++) {
    if (mask) {
      payloadData[i] = client.read() ^ maskingKey[i % 4];
    } else {
      payloadData[i] = client.read();
    }
  }
  payloadData[*payloadLength] = '\0';
  
  return opcode;
}

