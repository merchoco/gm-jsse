package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import javax.net.ssl.SSLProtocolException;

final class RenegotiationInfoExtension extends HelloExtension {
   private final byte[] renegotiated_connection;

   RenegotiationInfoExtension(byte[] var1, byte[] var2) {
      super(ExtensionType.EXT_RENEGOTIATION_INFO);
      if (var1.length != 0) {
         this.renegotiated_connection = new byte[var1.length + var2.length];
         System.arraycopy(var1, 0, this.renegotiated_connection, 0, var1.length);
         if (var2.length != 0) {
            System.arraycopy(var2, 0, this.renegotiated_connection, var1.length, var2.length);
         }
      } else {
         this.renegotiated_connection = new byte[0];
      }

   }

   RenegotiationInfoExtension(HandshakeInStream var1, int var2) throws IOException {
      super(ExtensionType.EXT_RENEGOTIATION_INFO);
      if (var2 < 1) {
         throw new SSLProtocolException("Invalid " + this.type + " extension");
      } else {
         int var3 = var1.getInt8();
         if (var3 + 1 != var2) {
            throw new SSLProtocolException("Invalid " + this.type + " extension");
         } else {
            this.renegotiated_connection = new byte[var3];
            if (var3 != 0) {
               var1.read(this.renegotiated_connection, 0, var3);
            }

         }
      }
   }

   int length() {
      return 5 + this.renegotiated_connection.length;
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putInt16(this.type.id);
      var1.putInt16(this.renegotiated_connection.length + 1);
      var1.putBytes8(this.renegotiated_connection);
   }

   boolean isEmpty() {
      return this.renegotiated_connection.length == 0;
   }

   byte[] getRenegotiatedConnection() {
      return this.renegotiated_connection;
   }

   public String toString() {
      return "Extension " + this.type + ", renegotiated_connection: " + (this.renegotiated_connection.length == 0 ? "<empty>" : Debug.toString(this.renegotiated_connection));
   }
}
