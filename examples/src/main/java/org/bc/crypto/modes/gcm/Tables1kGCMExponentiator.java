package org.bc.crypto.modes.gcm;

import java.util.Vector;
import org.bc.util.Arrays;

public class Tables1kGCMExponentiator implements GCMExponentiator {
   private Vector lookupPowX2;

   public void init(byte[] var1) {
      if (this.lookupPowX2 == null || !Arrays.areEqual(var1, (byte[])this.lookupPowX2.elementAt(0))) {
         this.lookupPowX2 = new Vector(8);
         this.lookupPowX2.addElement(Arrays.clone(var1));
      }
   }

   public void exponentiateX(long var1, byte[] var3) {
      byte[] var4 = GCMUtil.oneAsBytes();

      for(int var5 = 0; var1 > 0L; var1 >>>= 1) {
         if ((var1 & 1L) != 0L) {
            this.ensureAvailable(var5);
            GCMUtil.multiply(var4, (byte[])this.lookupPowX2.elementAt(var5));
         }

         ++var5;
      }

      System.arraycopy(var4, 0, var3, 0, 16);
   }

   private void ensureAvailable(int var1) {
      int var2 = this.lookupPowX2.size();
      if (var2 <= var1) {
         byte[] var3 = (byte[])this.lookupPowX2.elementAt(var2 - 1);

         do {
            var3 = Arrays.clone(var3);
            GCMUtil.multiply(var3, var3);
            this.lookupPowX2.addElement(var3);
            ++var2;
         } while(var2 <= var1);
      }

   }
}
