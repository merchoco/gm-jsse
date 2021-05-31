package org.bc.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.util.BigIntegers;

class DHParametersHelper {
   private static final BigInteger ONE = BigInteger.valueOf(1L);
   private static final BigInteger TWO = BigInteger.valueOf(2L);

   static BigInteger[] generateSafePrimes(int var0, int var1, SecureRandom var2) {
      int var5 = var0 - 1;

      BigInteger var3;
      BigInteger var4;
      do {
         do {
            var4 = new BigInteger(var5, 2, var2);
            var3 = var4.shiftLeft(1).add(ONE);
         } while(!var3.isProbablePrime(var1));
      } while(var1 > 2 && !var4.isProbablePrime(var1));

      return new BigInteger[]{var3, var4};
   }

   static BigInteger selectGenerator(BigInteger var0, BigInteger var1, SecureRandom var2) {
      BigInteger var3 = var0.subtract(TWO);

      BigInteger var4;
      do {
         BigInteger var5 = BigIntegers.createRandomInRange(TWO, var3, var2);
         var4 = var5.modPow(TWO, var0);
      } while(var4.equals(ONE));

      return var4;
   }
}
