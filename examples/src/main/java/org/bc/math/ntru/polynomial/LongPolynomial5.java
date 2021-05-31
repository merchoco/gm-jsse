package org.bc.math.ntru.polynomial;

import org.bc.util.Arrays;

public class LongPolynomial5 {
   private long[] coeffs;
   private int numCoeffs;

   public LongPolynomial5(IntegerPolynomial var1) {
      this.numCoeffs = var1.coeffs.length;
      this.coeffs = new long[(this.numCoeffs + 4) / 5];
      int var2 = 0;
      int var3 = 0;

      for(int var4 = 0; var4 < this.numCoeffs; ++var4) {
         this.coeffs[var2] |= (long)var1.coeffs[var4] << var3;
         var3 += 12;
         if (var3 >= 60) {
            var3 = 0;
            ++var2;
         }
      }

   }

   private LongPolynomial5(long[] var1, int var2) {
      this.coeffs = var1;
      this.numCoeffs = var2;
   }

   public LongPolynomial5 mult(TernaryPolynomial var1) {
      long[][] var2 = new long[5][this.coeffs.length + (var1.size() + 4) / 5 - 1];
      int[] var3 = var1.getOnes();

      int var5;
      int var6;
      int var7;
      int var8;
      for(int var4 = 0; var4 != var3.length; ++var4) {
         var5 = var3[var4];
         var6 = var5 / 5;
         var7 = var5 - var6 * 5;

         for(var8 = 0; var8 < this.coeffs.length; ++var8) {
            var2[var7][var6] = var2[var7][var6] + this.coeffs[var8] & 576319980446939135L;
            ++var6;
         }
      }

      int[] var18 = var1.getNegOnes();

      for(var5 = 0; var5 != var18.length; ++var5) {
         var6 = var18[var5];
         var7 = var6 / 5;
         var8 = var6 - var7 * 5;

         for(int var9 = 0; var9 < this.coeffs.length; ++var9) {
            var2[var8][var7] = 576601524159907840L + var2[var8][var7] - this.coeffs[var9] & 576319980446939135L;
            ++var7;
         }
      }

      long[] var19 = Arrays.copyOf(var2[0], var2[0].length + 1);

      int var11;
      int var12;
      long var13;
      long var15;
      int var17;
      for(var6 = 1; var6 <= 4; ++var6) {
         var7 = var6 * 12;
         var8 = 60 - var7;
         long var21 = (1L << var8) - 1L;
         var11 = var2[var6].length;

         for(var12 = 0; var12 < var11; ++var12) {
            var13 = var2[var6][var12] >> var8;
            var15 = var2[var6][var12] & var21;
            var19[var12] = var19[var12] + (var15 << var7) & 576319980446939135L;
            var17 = var12 + 1;
            var19[var17] = var19[var17] + var13 & 576319980446939135L;
         }
      }

      var6 = 12 * (this.numCoeffs % 5);

      for(var7 = this.coeffs.length - 1; var7 < var19.length; ++var7) {
         int var10;
         long var20;
         if (var7 == this.coeffs.length - 1) {
            var20 = this.numCoeffs == 5 ? 0L : var19[var7] >> var6;
            var10 = 0;
         } else {
            var20 = var19[var7];
            var10 = var7 * 5 - this.numCoeffs;
         }

         var11 = var10 / 5;
         var12 = var10 - var11 * 5;
         var13 = var20 << 12 * var12;
         var15 = var20 >> 12 * (5 - var12);
         var19[var11] = var19[var11] + var13 & 576319980446939135L;
         var17 = var11 + 1;
         if (var17 < this.coeffs.length) {
            var19[var17] = var19[var17] + var15 & 576319980446939135L;
         }
      }

      return new LongPolynomial5(var19, this.numCoeffs);
   }

   public IntegerPolynomial toIntegerPolynomial() {
      int[] var1 = new int[this.numCoeffs];
      int var2 = 0;
      int var3 = 0;

      for(int var4 = 0; var4 < this.numCoeffs; ++var4) {
         var1[var4] = (int)(this.coeffs[var2] >> var3 & 2047L);
         var3 += 12;
         if (var3 >= 60) {
            var3 = 0;
            ++var2;
         }
      }

      return new IntegerPolynomial(var1);
   }
}
