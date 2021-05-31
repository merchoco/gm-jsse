package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.util.ArrayList;
import javax.net.ssl.SSLProtocolException;

final class SupportedEllipticPointFormatsExtension extends HelloExtension {
   static final int FMT_UNCOMPRESSED = 0;
   static final int FMT_ANSIX962_COMPRESSED_PRIME = 1;
   static final int FMT_ANSIX962_COMPRESSED_CHAR2 = 2;
   static final HelloExtension DEFAULT = new SupportedEllipticPointFormatsExtension(new byte[1]);
   private final byte[] formats;

   private SupportedEllipticPointFormatsExtension(byte[] var1) {
      super(ExtensionType.EXT_EC_POINT_FORMATS);
      this.formats = var1;
   }

   SupportedEllipticPointFormatsExtension(HandshakeInStream var1, int var2) throws IOException {
      super(ExtensionType.EXT_EC_POINT_FORMATS);
      this.formats = var1.getBytes8();
      boolean var3 = false;
      byte[] var7 = this.formats;
      int var6 = this.formats.length;

      for(int var5 = 0; var5 < var6; ++var5) {
         byte var4 = var7[var5];
         if (var4 == 0) {
            var3 = true;
            break;
         }
      }

      if (!var3) {
         throw new SSLProtocolException("Peer does not support uncompressed points");
      }
   }

   int length() {
      return 5 + this.formats.length;
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putInt16(this.type.id);
      var1.putInt16(this.formats.length + 1);
      var1.putBytes8(this.formats);
   }

   private static String toString(byte var0) {
      int var1 = var0 & 255;
      switch(var1) {
      case 0:
         return "uncompressed";
      case 1:
         return "ansiX962_compressed_prime";
      case 2:
         return "ansiX962_compressed_char2";
      default:
         return "unknown-" + var1;
      }
   }

   public String toString() {
      ArrayList var1 = new ArrayList();
      byte[] var5 = this.formats;
      int var4 = this.formats.length;

      for(int var3 = 0; var3 < var4; ++var3) {
         byte var2 = var5[var3];
         var1.add(toString(var2));
      }

      return "Extension " + this.type + ", formats: " + var1;
   }
}
