package cn.gmssl.sun.security.ssl;

import java.io.IOException;

abstract class HelloExtension {
   final ExtensionType type;

   HelloExtension(ExtensionType var1) {
      this.type = var1;
   }

   abstract int length();

   abstract void send(HandshakeOutStream var1) throws IOException;

   public abstract String toString();
}
