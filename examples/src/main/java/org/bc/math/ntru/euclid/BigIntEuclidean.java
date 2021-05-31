package org.bc.math.ntru.euclid;

import java.math.BigInteger;

public class BigIntEuclidean {
   public BigInteger x;
   public BigInteger y;
   public BigInteger gcd;

   public static BigIntEuclidean calculate(BigInteger var0, BigInteger var1) {
      BigInteger var2 = BigInteger.ZERO;
      BigInteger var3 = BigInteger.ONE;
      BigInteger var4 = BigInteger.ONE;

      BigInteger var5;
      BigInteger var8;
      for(var5 = BigInteger.ZERO; !var1.equals(BigInteger.ZERO); var5 = var8) {
         BigInteger[] var6 = var0.divideAndRemainder(var1);
         BigInteger var7 = var6[0];
         var0 = var1;
         var1 = var6[1];
         var8 = var2;
         var2 = var3.subtract(var7.multiply(var2));
         var3 = var8;
         var8 = var4;
         var4 = var5.subtract(var7.multiply(var4));
      }

      BigIntEuclidean var9 = new BigIntEuclidean();
      var9.x = var3;
      var9.y = var5;
      var9.gcd = var0;
      return var9;
   }
}
