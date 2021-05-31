package org.bc.math.ec;

import java.math.BigInteger;

public class ECAlgorithms {
   public static ECPoint sumOfTwoMultiplies(ECPoint var0, BigInteger var1, ECPoint var2, BigInteger var3) {
      ECCurve var4 = var0.getCurve();
      if (!var4.equals(var2.getCurve())) {
         throw new IllegalArgumentException("P and Q must be on same curve");
      } else {
         if (var4 instanceof ECCurve.F2m) {
            ECCurve.F2m var5 = (ECCurve.F2m)var4;
            if (var5.isKoblitz()) {
               return var0.multiply(var1).add(var2.multiply(var3));
            }
         }

         return implShamirsTrick(var0, var1, var2, var3);
      }
   }

   public static ECPoint shamirsTrick(ECPoint var0, BigInteger var1, ECPoint var2, BigInteger var3) {
      if (!var0.getCurve().equals(var2.getCurve())) {
         throw new IllegalArgumentException("P and Q must be on same curve");
      } else {
         return implShamirsTrick(var0, var1, var2, var3);
      }
   }

   private static ECPoint implShamirsTrick(ECPoint var0, BigInteger var1, ECPoint var2, BigInteger var3) {
      int var4 = Math.max(var1.bitLength(), var3.bitLength());
      ECPoint var5 = var0.add(var2);
      ECPoint var6 = var0.getCurve().getInfinity();

      for(int var7 = var4 - 1; var7 >= 0; --var7) {
         var6 = var6.twice();
         if (var1.testBit(var7)) {
            if (var3.testBit(var7)) {
               var6 = var6.add(var5);
            } else {
               var6 = var6.add(var0);
            }
         } else if (var3.testBit(var7)) {
            var6 = var6.add(var2);
         }
      }

      return var6;
   }
}
