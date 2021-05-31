package org.bc.math.ntru.polynomial;

import java.security.SecureRandom;
import org.bc.math.ntru.util.Util;
import org.bc.util.Arrays;

public class DenseTernaryPolynomial extends IntegerPolynomial implements TernaryPolynomial {
   DenseTernaryPolynomial(int var1) {
      super(var1);
      this.checkTernarity();
   }

   public DenseTernaryPolynomial(IntegerPolynomial var1) {
      this(var1.coeffs);
   }

   public DenseTernaryPolynomial(int[] var1) {
      super(var1);
      this.checkTernarity();
   }

   private void checkTernarity() {
      for(int var1 = 0; var1 != this.coeffs.length; ++var1) {
         int var2 = this.coeffs[var1];
         if (var2 < -1 || var2 > 1) {
            throw new IllegalStateException("Illegal value: " + var2 + ", must be one of {-1, 0, 1}");
         }
      }

   }

   public static DenseTernaryPolynomial generateRandom(int var0, int var1, int var2, SecureRandom var3) {
      int[] var4 = Util.generateRandomTernary(var0, var1, var2, var3);
      return new DenseTernaryPolynomial(var4);
   }

   public static DenseTernaryPolynomial generateRandom(int var0, SecureRandom var1) {
      DenseTernaryPolynomial var2 = new DenseTernaryPolynomial(var0);

      for(int var3 = 0; var3 < var0; ++var3) {
         var2.coeffs[var3] = var1.nextInt(3) - 1;
      }

      return var2;
   }

   public IntegerPolynomial mult(IntegerPolynomial var1, int var2) {
      if (var2 == 2048) {
         IntegerPolynomial var3 = (IntegerPolynomial)var1.clone();
         var3.modPositive(2048);
         LongPolynomial5 var4 = new LongPolynomial5(var3);
         return var4.mult(this).toIntegerPolynomial();
      } else {
         return super.mult(var1, var2);
      }
   }

   public int[] getOnes() {
      int var1 = this.coeffs.length;
      int[] var2 = new int[var1];
      int var3 = 0;

      for(int var4 = 0; var4 < var1; ++var4) {
         int var5 = this.coeffs[var4];
         if (var5 == 1) {
            var2[var3++] = var4;
         }
      }

      return Arrays.copyOf(var2, var3);
   }

   public int[] getNegOnes() {
      int var1 = this.coeffs.length;
      int[] var2 = new int[var1];
      int var3 = 0;

      for(int var4 = 0; var4 < var1; ++var4) {
         int var5 = this.coeffs[var4];
         if (var5 == -1) {
            var2[var3++] = var4;
         }
      }

      return Arrays.copyOf(var2, var3);
   }

   public int size() {
      return this.coeffs.length;
   }
}
