package org.bc.crypto.engines;

import java.math.BigInteger;
import java.util.Random;

public class MyBigInteger {
   public static BigInteger gen(BigInteger var0, Random var1) {
      BigInteger var2 = null;
      int var3 = var0.bitLength();
      int var4 = var3 / 8;
      byte var5 = 64;
      int var6 = 0;

      while(true) {
         do {
            var2 = new BigInteger(var3, var1);
         } while(var2.equals(BigInteger.ZERO));

         if (var2.compareTo(var0) < 0) {
            int var7 = var2.bitLength() / 8;
            if (var7 == var4) {
               ++var6;
               if (var6 > var5) {
                  return var2;
               }
            }
         }
      }
   }
}
