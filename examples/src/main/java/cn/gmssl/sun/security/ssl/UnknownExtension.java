package cn.gmssl.sun.security.ssl;

import java.io.IOException;

final class UnknownExtension extends HelloExtension {
   private final byte[] data;

   UnknownExtension(HandshakeInStream var1, int var2, ExtensionType var3) throws IOException {
      super(var3);
      this.data = new byte[var2];
      if (var2 != 0) {
         var1.read(this.data);
      }

   }

   int length() {
      return 4 + this.data.length;
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putInt16(this.type.id);
      var1.putBytes16(this.data);
   }

   public String toString() {
      return "Unsupported extension " + this.type + ", data: " + Debug.toString(this.data);
   }
}
