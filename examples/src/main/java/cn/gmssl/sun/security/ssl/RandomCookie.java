package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;

final class RandomCookie {
   byte[] random_bytes;

   RandomCookie(SecureRandom var1) {
      long var2 = System.currentTimeMillis() / 1000L;
      int var4;
      if (var2 < 2147483647L) {
         var4 = (int)var2;
      } else {
         var4 = Integer.MAX_VALUE;
      }

      this.random_bytes = new byte[32];
      var1.nextBytes(this.random_bytes);
      this.random_bytes[0] = (byte)(var4 >> 24);
      this.random_bytes[1] = (byte)(var4 >> 16);
      this.random_bytes[2] = (byte)(var4 >> 8);
      this.random_bytes[3] = (byte)var4;
   }

   RandomCookie(HandshakeInStream var1) throws IOException {
      this.random_bytes = new byte[32];
      var1.read(this.random_bytes, 0, 32);
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.write(this.random_bytes, 0, 32);
   }

   void print(PrintStream var1) {
      int var3 = this.random_bytes[0] << 24;
      var3 += this.random_bytes[1] << 16;
      var3 += this.random_bytes[2] << 8;
      var3 += this.random_bytes[3];
      var1.print("GMT: " + var3 + " ");
      var1.print("bytes = { ");

      for(int var2 = 4; var2 < 32; ++var2) {
         if (var2 != 4) {
            var1.print(", ");
         }

         var1.print(this.random_bytes[var2] & 255);
      }

      var1.println(" }");
   }
}
