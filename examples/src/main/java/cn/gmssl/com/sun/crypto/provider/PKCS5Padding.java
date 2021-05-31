package cn.gmssl.com.sun.crypto.provider;

import javax.crypto.ShortBufferException;

final class PKCS5Padding implements Padding {
   private int blockSize;

   PKCS5Padding(int var1) {
      this.blockSize = var1;
   }

   public void padWithLen(byte[] var1, int var2, int var3) throws ShortBufferException {
      if (var1 != null) {
         if (var2 + var3 > var1.length) {
            throw new ShortBufferException("Buffer too small to hold padding");
         } else {
            byte var4 = (byte)(var3 & 255);

            for(int var5 = 0; var5 < var3; ++var5) {
               var1[var5 + var2] = var4;
            }

         }
      }
   }

   public int unpad(byte[] var1, int var2, int var3) {
      if (var1 != null && var3 != 0) {
         byte var4 = var1[var2 + var3 - 1];
         int var5 = var4 & 255;
         if (var5 >= 1 && var5 <= this.blockSize) {
            int var6 = var2 + var3 - (var4 & 255);
            if (var6 < var2) {
               return -1;
            } else {
               for(int var7 = 0; var7 < (var4 & 255); ++var7) {
                  if (var1[var6 + var7] != var4) {
                     return -1;
                  }
               }

               return var6;
            }
         } else {
            return -1;
         }
      } else {
         return 0;
      }
   }

   public int padLength(int var1) {
      int var2 = this.blockSize - var1 % this.blockSize;
      return var2;
   }
}
