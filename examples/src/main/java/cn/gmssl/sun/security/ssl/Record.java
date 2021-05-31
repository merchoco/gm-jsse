package cn.gmssl.sun.security.ssl;

interface Record {
   byte ct_change_cipher_spec = 20;
   byte ct_alert = 21;
   byte ct_handshake = 22;
   byte ct_application_data = 23;
   int headerSize = 5;
   int maxExpansion = 1024;
   int trailerSize = 20;
   int maxDataSize = 16384;
   int maxPadding = 256;
   int maxIVLength = 256;
   int maxRecordSize = 16921;
   int maxLargeRecordSize = 33305;
   int maxAlertRecordSize = 539;
}
