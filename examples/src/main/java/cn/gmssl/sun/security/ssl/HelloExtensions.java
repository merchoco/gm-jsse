package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLProtocolException;

final class HelloExtensions {
   private List<HelloExtension> extensions;
   private int encodedLength;

   HelloExtensions() {
      this.extensions = Collections.emptyList();
   }

   HelloExtensions(HandshakeInStream var1) throws IOException {
      int var2 = var1.getInt16();
      this.extensions = new ArrayList();

      int var4;
      for(this.encodedLength = var2 + 2; var2 > 0; var2 -= var4 + 4) {
         int var3 = var1.getInt16();
         var4 = var1.getInt16();
         ExtensionType var5 = ExtensionType.get(var3);
         Object var6;
         if (var5 == ExtensionType.EXT_SERVER_NAME) {
            var6 = new ServerNameExtension(var1, var4);
         } else if (var5 == ExtensionType.EXT_SIGNATURE_ALGORITHMS) {
            var6 = new SignatureAlgorithmsExtension(var1, var4);
         } else if (var5 == ExtensionType.EXT_ELLIPTIC_CURVES) {
            var6 = new SupportedEllipticCurvesExtension(var1, var4);
         } else if (var5 == ExtensionType.EXT_EC_POINT_FORMATS) {
            var6 = new SupportedEllipticPointFormatsExtension(var1, var4);
         } else if (var5 == ExtensionType.EXT_RENEGOTIATION_INFO) {
            var6 = new RenegotiationInfoExtension(var1, var4);
         } else {
            var6 = new UnknownExtension(var1, var4, var5);
         }

         this.extensions.add((HelloExtension) var6);
      }

      if (var2 != 0) {
         throw new SSLProtocolException("Error parsing extensions: extra data");
      }
   }

   List<HelloExtension> list() {
      return this.extensions;
   }

   void add(HelloExtension var1) {
      if (this.extensions.isEmpty()) {
         this.extensions = new ArrayList();
      }

      this.extensions.add(var1);
      this.encodedLength = -1;
   }

   HelloExtension get(ExtensionType var1) {
      Iterator var3 = this.extensions.iterator();

      while(var3.hasNext()) {
         HelloExtension var2 = (HelloExtension)var3.next();
         if (var2.type == var1) {
            return var2;
         }
      }

      return null;
   }

   int length() {
      if (this.encodedLength >= 0) {
         return this.encodedLength;
      } else {
         if (this.extensions.isEmpty()) {
            this.encodedLength = 0;
         } else {
            this.encodedLength = 2;

            HelloExtension var1;
            for(Iterator var2 = this.extensions.iterator(); var2.hasNext(); this.encodedLength += var1.length()) {
               var1 = (HelloExtension)var2.next();
            }
         }

         return this.encodedLength;
      }
   }

   void send(HandshakeOutStream var1) throws IOException {
      int var2 = this.length();
      if (var2 != 0) {
         var1.putInt16(var2 - 2);
         Iterator var4 = this.extensions.iterator();

         while(var4.hasNext()) {
            HelloExtension var3 = (HelloExtension)var4.next();
            var3.send(var1);
         }

      }
   }

   void print(PrintStream var1) throws IOException {
      Iterator var3 = this.extensions.iterator();

      while(var3.hasNext()) {
         HelloExtension var2 = (HelloExtension)var3.next();
         var1.println(var2.toString());
      }

   }
}
