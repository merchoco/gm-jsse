package org.bc.crypto.modes.gcm;

import org.bc.util.Arrays;

public class BasicGCMExponentiator implements GCMExponentiator {
   private byte[] x;

   public void init(byte[] var1) {
      this.x = Arrays.clone(var1);
   }

   public void exponentiateX(long var1, byte[] var3) {
      byte[] var4 = GCMUtil.oneAsBytes();
      if (var1 > 0L) {
         byte[] var5 = Arrays.clone(this.x);

         do {
            if ((var1 & 1L) != 0L) {
               GCMUtil.multiply(var4, var5);
            }

            GCMUtil.multiply(var5, var5);
            var1 >>>= 1;
         } while(var1 > 0L);
      }

      System.arraycopy(var4, 0, var3, 0, 16);
   }
}
