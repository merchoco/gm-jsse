package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.PrintStream;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

final class ECDHClientKeyExchange extends HandshakeMessage {
   private byte[] encodedPoint;

   int messageType() {
      return 16;
   }

   byte[] getEncodedPoint() {
      return this.encodedPoint;
   }

   ECDHClientKeyExchange(PublicKey var1) {
      ECPublicKey var2 = (ECPublicKey)var1;
      ECPoint var3 = var2.getW();
      ECParameterSpec var4 = var2.getParams();
      this.encodedPoint = JsseJce.encodePoint(var3, var4.getCurve());
   }

   ECDHClientKeyExchange(HandshakeInStream var1) throws IOException {
      this.encodedPoint = var1.getBytes8();
   }

   int messageLength() {
      return this.encodedPoint.length + 1;
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putBytes8(this.encodedPoint);
   }

   void print(PrintStream var1) throws IOException {
      var1.println("*** ECDHClientKeyExchange");
      if (debug != null && Debug.isOn("verbose")) {
         Debug.println(var1, "ECDH Public value", this.encodedPoint);
      }

   }
}
