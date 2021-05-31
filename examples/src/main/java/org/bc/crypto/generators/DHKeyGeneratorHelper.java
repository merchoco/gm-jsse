package org.bc.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.params.DHParameters;
import org.bc.util.BigIntegers;

class DHKeyGeneratorHelper {
   static final DHKeyGeneratorHelper INSTANCE = new DHKeyGeneratorHelper();
   private static final BigInteger ONE = BigInteger.valueOf(1L);
   private static final BigInteger TWO = BigInteger.valueOf(2L);

   BigInteger calculatePrivate(DHParameters var1, SecureRandom var2) {
      BigInteger var3 = var1.getP();
      int var4 = var1.getL();
      if (var4 != 0) {
         return (new BigInteger(var4, var2)).setBit(var4 - 1);
      } else {
         BigInteger var5 = TWO;
         int var6 = var1.getM();
         if (var6 != 0) {
            var5 = ONE.shiftLeft(var6 - 1);
         }

         BigInteger var7 = var3.subtract(TWO);
         BigInteger var8 = var1.getQ();
         if (var8 != null) {
            var7 = var8.subtract(TWO);
         }

         return BigIntegers.createRandomInRange(var5, var7, var2);
      }
   }

   BigInteger calculatePublic(DHParameters var1, BigInteger var2) {
      return var1.getG().modPow(var2, var1.getP());
   }
}
