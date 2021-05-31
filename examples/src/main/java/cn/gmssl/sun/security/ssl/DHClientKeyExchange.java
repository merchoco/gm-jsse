package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;

final class DHClientKeyExchange extends HandshakeMessage {
   private byte[] dh_Yc;

   int messageType() {
      return 16;
   }

   BigInteger getClientPublicKey() {
      return new BigInteger(1, this.dh_Yc);
   }

   DHClientKeyExchange(BigInteger var1) {
      this.dh_Yc = toByteArray(var1);
   }

   DHClientKeyExchange() {
      this.dh_Yc = null;
   }

   DHClientKeyExchange(HandshakeInStream var1) throws IOException {
      this.dh_Yc = var1.getBytes16();
   }

   int messageLength() {
      return this.dh_Yc == null ? 0 : this.dh_Yc.length + 2;
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putBytes16(this.dh_Yc);
   }

   void print(PrintStream var1) throws IOException {
      var1.println("*** ClientKeyExchange, DH");
      if (debug != null && Debug.isOn("verbose")) {
         Debug.println(var1, "DH Public key", this.dh_Yc);
      }

   }
}
