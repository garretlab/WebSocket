void base64Encode(char *input, char *output) {
  const char *encTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int inPos = 0, outPos = 0;
  int remainder = 0;

  for (char *p = input; *p; p++, inPos++) {
    switch (remainder = inPos % 3) {
    case 0:
      output[outPos++] = encTable[((input[inPos] >> 2) & 0x3f)];
      break;
    case 1:
      output[outPos++] = encTable[((input[inPos - 1] << 4) & 0x30) | ((input[inPos] >> 4) & 0x0f)];
      break;
    case 2:
      output[outPos++] = encTable[((input[inPos - 1] << 2) & 0x3c) | ((input[inPos] >> 6) & 0x03)];
      output[outPos++] = encTable[(input[inPos] & 0x3f)];
      break;
    }
  }
  
  if (remainder != 2) { /* inPos is incremented at the for loop above. */
    output[outPos++] = encTable[(input[inPos - 1] << (4 - 2 * remainder)) & 0x3f]; /* Pads 0s */
  }
  
  while (outPos % 4) {
    output[outPos++] = '='; /* Pads '='s */
  }

  output[outPos] = '\0';
}


