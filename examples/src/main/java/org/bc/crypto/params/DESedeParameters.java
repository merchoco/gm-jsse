package org.bc.crypto.params;

public class DESedeParameters extends DESParameters {
   public static final int DES_EDE_KEY_LENGTH = 24;

   public DESedeParameters(byte[] var1) {
      super(var1);
      if (isWeakKey(var1, 0, var1.length)) {
         throw new IllegalArgumentException("attempt to create weak DESede key");
      }
   }

   public static boolean isWeakKey(byte[] var0, int var1, int var2) {
      for(int var3 = var1; var3 < var2; var3 += 8) {
         if (DESParameters.isWeakKey(var0, var3)) {
            return true;
         }
      }

      return false;
   }

   public static boolean isWeakKey(byte[] var0, int var1) {
      return isWeakKey(var0, var1, var0.length - var1);
   }
}
