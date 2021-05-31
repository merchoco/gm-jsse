package org.bc.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.params.DSAParameters;
import org.bc.crypto.params.DSAValidationParameters;
import org.bc.util.Arrays;
import org.bc.util.BigIntegers;

public class DSAParametersGenerator {
   private int L;
   private int N;
   private int certainty;
   private SecureRandom random;
   private static final BigInteger ZERO = BigInteger.valueOf(0L);
   private static final BigInteger ONE = BigInteger.valueOf(1L);
   private static final BigInteger TWO = BigInteger.valueOf(2L);

   public void init(int var1, int var2, SecureRandom var3) {
      this.init(var1, getDefaultN(var1), var2, var3);
   }

   private void init(int var1, int var2, int var3, SecureRandom var4) {
      this.L = var1;
      this.N = var2;
      this.certainty = var3;
      this.random = var4;
   }

   public DSAParameters generateParameters() {
      return this.L > 1024 ? this.generateParameters_FIPS186_3() : this.generateParameters_FIPS186_2();
   }

   private DSAParameters generateParameters_FIPS186_2() {
      byte[] var1 = new byte[20];
      byte[] var2 = new byte[20];
      byte[] var3 = new byte[20];
      byte[] var4 = new byte[20];
      SHA1Digest var5 = new SHA1Digest();
      int var6 = (this.L - 1) / 160;
      byte[] var7 = new byte[this.L / 8];

      while(true) {
         BigInteger var15;
         do {
            this.random.nextBytes(var1);
            hash(var5, var1, var2);
            System.arraycopy(var1, 0, var3, 0, var1.length);
            inc(var3);
            hash(var5, var3, var3);

            for(int var8 = 0; var8 != var4.length; ++var8) {
               var4[var8] = (byte)(var2[var8] ^ var3[var8]);
            }

            var4[0] |= -128;
            var4[19] = (byte)(var4[19] | 1);
            var15 = new BigInteger(1, var4);
         } while(!var15.isProbablePrime(this.certainty));

         byte[] var9 = Arrays.clone(var1);
         inc(var9);

         for(int var10 = 0; var10 < 4096; ++var10) {
            for(int var11 = 0; var11 < var6; ++var11) {
               inc(var9);
               hash(var5, var9, var2);
               System.arraycopy(var2, 0, var7, var7.length - (var11 + 1) * var2.length, var2.length);
            }

            inc(var9);
            hash(var5, var9, var2);
            System.arraycopy(var2, var2.length - (var7.length - var6 * var2.length), var7, 0, var7.length - var6 * var2.length);
            var7[0] |= -128;
            BigInteger var16 = new BigInteger(1, var7);
            BigInteger var12 = var16.mod(var15.shiftLeft(1));
            BigInteger var13 = var16.subtract(var12.subtract(ONE));
            if (var13.bitLength() == this.L && var13.isProbablePrime(this.certainty)) {
               BigInteger var14 = calculateGenerator_FIPS186_2(var13, var15, this.random);
               return new DSAParameters(var13, var15, var14, new DSAValidationParameters(var1, var10));
            }
         }
      }
   }

   private static BigInteger calculateGenerator_FIPS186_2(BigInteger var0, BigInteger var1, SecureRandom var2) {
      BigInteger var3 = var0.subtract(ONE).divide(var1);
      BigInteger var4 = var0.subtract(TWO);

      BigInteger var6;
      do {
         BigInteger var5 = BigIntegers.createRandomInRange(TWO, var4, var2);
         var6 = var5.modPow(var3, var0);
      } while(var6.bitLength() <= 1);

      return var6;
   }

   private DSAParameters generateParameters_FIPS186_3() {
      SHA256Digest var1 = new SHA256Digest();
      int var2 = var1.getDigestSize() * 8;
      int var3 = this.N;
      byte[] var4 = new byte[var3 / 8];
      int var5 = (this.L - 1) / var2;
      int var6 = (this.L - 1) % var2;
      byte[] var7 = new byte[var1.getDigestSize()];

      while(true) {
         while(true) {
            this.random.nextBytes(var4);
            hash(var1, var4, var7);
            BigInteger var8 = (new BigInteger(1, var7)).mod(ONE.shiftLeft(this.N - 1));
            BigInteger var9 = ONE.shiftLeft(this.N - 1).add(var8).add(ONE).subtract(var8.mod(TWO));
            if (var9.isProbablePrime(this.certainty)) {
               byte[] var10 = Arrays.clone(var4);
               int var11 = 4 * this.L;

               for(int var12 = 0; var12 < var11; ++var12) {
                  BigInteger var13 = ZERO;
                  int var14 = 0;

                  BigInteger var16;
                  for(int var15 = 0; var14 <= var5; var15 += var2) {
                     inc(var10);
                     hash(var1, var10, var7);
                     var16 = new BigInteger(1, var7);
                     if (var14 == var5) {
                        var16 = var16.mod(ONE.shiftLeft(var6));
                     }

                     var13 = var13.add(var16.shiftLeft(var15));
                     ++var14;
                  }

                  BigInteger var18 = var13.add(ONE.shiftLeft(this.L - 1));
                  BigInteger var19 = var18.mod(var9.shiftLeft(1));
                  var16 = var18.subtract(var19.subtract(ONE));
                  if (var16.bitLength() == this.L && var16.isProbablePrime(this.certainty)) {
                     BigInteger var17 = calculateGenerator_FIPS186_3_Unverifiable(var16, var9, this.random);
                     return new DSAParameters(var16, var9, var17, new DSAValidationParameters(var4, var12));
                  }
               }
            }
         }
      }
   }

   private static BigInteger calculateGenerator_FIPS186_3_Unverifiable(BigInteger var0, BigInteger var1, SecureRandom var2) {
      return calculateGenerator_FIPS186_2(var0, var1, var2);
   }

   private static void hash(Digest var0, byte[] var1, byte[] var2) {
      var0.update(var1, 0, var1.length);
      var0.doFinal(var2, 0);
   }

   private static int getDefaultN(int var0) {
      return var0 > 1024 ? 256 : 160;
   }

   private static void inc(byte[] var0) {
      for(int var1 = var0.length - 1; var1 >= 0; --var1) {
         byte var2 = (byte)(var0[var1] + 1 & 255);
         var0[var1] = var2;
         if (var2 != 0) {
            break;
         }
      }

   }
}
