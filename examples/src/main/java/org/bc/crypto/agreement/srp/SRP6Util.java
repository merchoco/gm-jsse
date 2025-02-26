package org.bc.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.CryptoException;
import org.bc.crypto.Digest;
import org.bc.util.BigIntegers;

public class SRP6Util {
   private static BigInteger ZERO = BigInteger.valueOf(0L);
   private static BigInteger ONE = BigInteger.valueOf(1L);

   public static BigInteger calculateK(Digest var0, BigInteger var1, BigInteger var2) {
      return hashPaddedPair(var0, var1, var1, var2);
   }

   public static BigInteger calculateU(Digest var0, BigInteger var1, BigInteger var2, BigInteger var3) {
      return hashPaddedPair(var0, var1, var2, var3);
   }

   public static BigInteger calculateX(Digest var0, BigInteger var1, byte[] var2, byte[] var3, byte[] var4) {
      byte[] var5 = new byte[var0.getDigestSize()];
      var0.update(var3, 0, var3.length);
      var0.update((byte)58);
      var0.update(var4, 0, var4.length);
      var0.doFinal(var5, 0);
      var0.update(var2, 0, var2.length);
      var0.update(var5, 0, var5.length);
      var0.doFinal(var5, 0);
      return new BigInteger(1, var5);
   }

   public static BigInteger generatePrivateValue(Digest var0, BigInteger var1, BigInteger var2, SecureRandom var3) {
      int var4 = Math.min(256, var1.bitLength() / 2);
      BigInteger var5 = ONE.shiftLeft(var4 - 1);
      BigInteger var6 = var1.subtract(ONE);
      return BigIntegers.createRandomInRange(var5, var6, var3);
   }

   public static BigInteger validatePublicValue(BigInteger var0, BigInteger var1) throws CryptoException {
      var1 = var1.mod(var0);
      if (var1.equals(ZERO)) {
         throw new CryptoException("Invalid public value: 0");
      } else {
         return var1;
      }
   }

   private static BigInteger hashPaddedPair(Digest var0, BigInteger var1, BigInteger var2, BigInteger var3) {
      int var4 = (var1.bitLength() + 7) / 8;
      byte[] var5 = getPadded(var2, var4);
      byte[] var6 = getPadded(var3, var4);
      var0.update(var5, 0, var5.length);
      var0.update(var6, 0, var6.length);
      byte[] var7 = new byte[var0.getDigestSize()];
      var0.doFinal(var7, 0);
      return new BigInteger(1, var7);
   }

   private static byte[] getPadded(BigInteger var0, int var1) {
      byte[] var2 = BigIntegers.asUnsignedByteArray(var0);
      if (var2.length < var1) {
         byte[] var3 = new byte[var1];
         System.arraycopy(var2, 0, var3, var1 - var2.length, var2.length);
         var2 = var3;
      }

      return var2;
   }
}
