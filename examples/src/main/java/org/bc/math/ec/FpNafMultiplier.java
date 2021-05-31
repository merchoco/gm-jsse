package org.bc.math.ec;

import java.math.BigInteger;

class FpNafMultiplier implements ECMultiplier {
   public ECPoint multiply(ECPoint var1, BigInteger var2, PreCompInfo var3) {
      BigInteger var4 = var2;
      BigInteger var5 = var2.multiply(BigInteger.valueOf(3L));
      ECPoint var6 = var1.negate();
      ECPoint var7 = var1;

      for(int var8 = var5.bitLength() - 2; var8 > 0; --var8) {
         var7 = var7.twice();
         boolean var9 = var5.testBit(var8);
         boolean var10 = var4.testBit(var8);
         if (var9 != var10) {
            var7 = var7.add(var9 ? var1 : var6);
         }
      }

      return var7;
   }
}
