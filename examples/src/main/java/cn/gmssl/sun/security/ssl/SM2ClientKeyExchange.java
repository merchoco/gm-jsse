package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.PrintStream;

final class SM2ClientKeyExchange extends HandshakeMessage {
   private byte[] encodedPoint;

   int messageType() {
      return 16;
   }

   byte[] getEncodedPoint() {
      return this.encodedPoint;
   }

   SM2ClientKeyExchange(byte[] var1) {
      this.encodedPoint = var1;
   }

   SM2ClientKeyExchange(HandshakeInStream var1) throws IOException {
      var1.read();
      var1.read();
      var1.read();
      this.encodedPoint = var1.getBytes8();
   }

   int messageLength() {
      return 3 + this.encodedPoint.length + 1;
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putInt8(3);
      var1.putInt16(23);
      var1.putBytes8(this.encodedPoint);
   }

   void print(PrintStream var1) throws IOException {
      var1.println("*** SM2ClientKeyExchange");
      if (debug != null && Debug.isOn("verbose")) {
         Debug.println(var1, "SM2 Public value", this.encodedPoint);
      }

   }
}
