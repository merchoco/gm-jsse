package org.bc.crypto.paddings;

import java.security.SecureRandom;
import org.bc.crypto.InvalidCipherTextException;

public class PKCS7Padding implements BlockCipherPadding {
   public void init(SecureRandom var1) throws IllegalArgumentException {
   }

   public String getPaddingName() {
      return "PKCS7";
   }

   public int addPadding(byte[] var1, int var2) {
      byte var3;
      for(var3 = (byte)(var1.length - var2); var2 < var1.length; ++var2) {
         var1[var2] = var3;
      }

      return var3;
   }

   public int padCount(byte[] var1) throws InvalidCipherTextException {
      int var2 = var1[var1.length - 1] & 255;
      if (var2 <= var1.length && var2 != 0) {
         for(int var3 = 1; var3 <= var2; ++var3) {
            if (var1[var1.length - var3] != var2) {
               throw new InvalidCipherTextException("pad block corrupted");
            }
         }

         return var2;
      } else {
         throw new InvalidCipherTextException("pad block corrupted");
      }
   }
}
