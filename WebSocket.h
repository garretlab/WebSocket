#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <Ethernet.h>
#include <Arduino.h>

#define WS_MAX_PAYLOAD_LENGTH  125
#define WS_MAX_LINE_LENGTH     128
#define WS_KEY_LENGTH           32

#define WS_OK 1
#define WS_CONNECTED 2
#define WS_NO_CLIENT 3
#define WS_DATA_RECEIVCED 4
#define WS_NO_DATA 5
#define WS_CLOSED 6
#define WS_PROTOCOL_ERROR 7
#define WS_LINE_TOO_LONG  -1
#define WS_STATUS_MISMATCH -2
#define WS_NOT_SUPPORTED -3
#define WS_ERROR -127

#define WS_SENDTO_ALL -1

#define WS_HAS_GET                    0x01
#define WS_HAS_HOST                   0x02     
#define WS_HAS_UPGRADE                0x04
#define WS_HAS_CONNECTION             0x08
#define WS_HAS_SEC_WEBSOCKET_KEY      0x10
#define WS_HAS_SEC_WEBSOCKET_VERSION  0x20
#define WS_HAS_ALL_HEADERS            0x3f
#define WS_HAS_SUBPROTOCOL            0x40

#define WS_FRAME_TEXT   0x01
#define WS_FRAME_BINARY 0x02
#define WS_FRAME_CLOSE  0x08
#define WS_FRAME_FIN    0x80

#define WS_CLOSE_NORMAL          1000
#define WS_CLOSE_PROTOCOL_ERROR  1002
#define WS_CLOSE_MESSAGE_TOO_BIG 1009

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef enum {
  CONNECTING = 0,
  OPEN = 1,
  CLOSING = 2,
  CLOSED = 3, 
} wsStatus;

typedef struct {
  char *header;
  char *value;
  uint8_t validation;
  char *variable;
} wsHeader;

typedef void (*onOpen_t)(char *requestURI, int clientId);
typedef void (*onMessage_t)(char *payload, int payloadLength, int clientId);
typedef void (*onClose_t)(int clientId);
typedef void (*onError_t)(int clientId);

class WebSocket {
public:
  WebSocket(uint16_t port, char *supportedProtocol, onOpen_t onOpen = NULL, onMessage_t onMessage = NULL, onClose_t onClose = NULL, onError_t onError = NULL);
  wsStatus status[MAX_SOCK_NUM];
  void begin();
  int available(int *clientId);
  int sendText(char *text, int clientId);
  int sendBinary(uint8_t *data, uint8_t dataLength, int clientId);
  int sendPayload(uint8_t *payLoadData, uint8_t payloadLength, uint8_t opcode, int clientId);
  int sendClose(uint16_t statusCode, int clientId);
private:
  EthernetServer server;
  EthernetClient client[MAX_SOCK_NUM];
  uint16_t port;
  char *supportedProtocol;
  onOpen_t onOpen;
  onMessage_t onMessage;
  onClose_t onClose;
  onError_t onError;
  int handshake(char *requestURI, int clientId);
  int readHTMLHeader(uint8_t *buffer, uint8_t bufferLength, int clientId); 
  int readFrame(char *frame, int *payloadLength, int clientId);
};

#endif /* WEBSOCKET_H */

