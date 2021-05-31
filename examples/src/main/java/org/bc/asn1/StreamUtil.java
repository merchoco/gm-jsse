package org.bc.asn1;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

class StreamUtil {
   private static final long MAX_MEMORY = Runtime.getRuntime().maxMemory();

   static int findLimit(InputStream var0) {
      if (var0 instanceof LimitedInputStream) {
         return ((LimitedInputStream)var0).getRemaining();
      } else if (var0 instanceof ASN1InputStream) {
         return ((ASN1InputStream)var0).getLimit();
      } else if (var0 instanceof ByteArrayInputStream) {
         return ((ByteArrayInputStream)var0).available();
      } else {
         if (var0 instanceof FileInputStream) {
            try {
               long var1 = ((FileInputStream)var0).getChannel().size();
               if (var1 < 2147483647L) {
                  return (int)var1;
               }
            } catch (IOException var3) {
               ;
            }
         }

         return MAX_MEMORY > 2147483647L ? Integer.MAX_VALUE : (int)MAX_MEMORY;
      }
   }

   static int calculateBodyLength(int var0) {
      int var1 = 1;
      if (var0 > 127) {
         int var2 = 1;

         for(int var3 = var0; (var3 >>>= 8) != 0; ++var2) {
            ;
         }

         for(int var4 = (var2 - 1) * 8; var4 >= 0; var4 -= 8) {
            ++var1;
         }
      }

      return var1;
   }

   static int calculateTagLength(int var0) throws IOException {
      int var1 = 1;
      if (var0 >= 31) {
         if (var0 < 128) {
            ++var1;
         } else {
            byte[] var2 = new byte[5];
            int var3 = var2.length;
            --var3;
            var2[var3] = (byte)(var0 & 127);

            do {
               var0 >>= 7;
               --var3;
               var2[var3] = (byte)(var0 & 127 | 128);
            } while(var0 > 127);

            var1 += var2.length - var3;
         }
      }

      return var1;
   }
}
