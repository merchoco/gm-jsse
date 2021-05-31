package org.bc.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class BigIntegers {
   private static final int MAX_ITERATIONS = 1000;
   private static final BigInteger ZERO = BigInteger.valueOf(0L);

   public static byte[] asUnsignedByteArray(BigInteger var0) {
      byte[] var1 = var0.toByteArray();
      if (var1[0] == 0) {
         byte[] var2 = new byte[var1.length - 1];
         System.arraycopy(var1, 1, var2, 0, var2.length);
         return var2;
      } else {
         return var1;
      }
   }

   public static byte[] asUnsignedByteArray(int var0, BigInteger var1) {
      byte[] var2 = var1.toByteArray();
      byte[] var3;
      if (var2[0] == 0) {
         if (var2.length - 1 > var0) {
            throw new IllegalArgumentException("standard length exceeded for value");
         } else {
            var3 = new byte[var0];
            System.arraycopy(var2, 1, var3, var3.length - (var2.length - 1), var2.length - 1);
            return var3;
         }
      } else if (var2.length == var0) {
         return var2;
      } else if (var2.length > var0) {
         throw new IllegalArgumentException("standard length exceeded for value");
      } else {
         var3 = new byte[var0];
         System.arraycopy(var2, 0, var3, var3.length - var2.length, var2.length);
         return var3;
      }
   }

   public static BigInteger createRandomInRange(BigInteger var0, BigInteger var1, SecureRandom var2) {
      int var3 = var0.compareTo(var1);
      if (var3 >= 0) {
         if (var3 > 0) {
            throw new IllegalArgumentException("'min' may not be greater than 'max'");
         } else {
            return var0;
         }
      } else if (var0.bitLength() > var1.bitLength() / 2) {
         return createRandomInRange(ZERO, var1.subtract(var0), var2).add(var0);
      } else {
         for(int var4 = 0; var4 < 1000; ++var4) {
            BigInteger var5 = new BigInteger(var1.bitLength(), var2);
            if (var5.compareTo(var0) >= 0 && var5.compareTo(var1) <= 0) {
               return var5;
            }
         }

         return (new BigInteger(var1.subtract(var0).bitLength() - 1, var2)).add(var0);
      }
   }
}
