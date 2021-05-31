package org.bc.math.ntru.polynomial;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import org.bc.util.Arrays;

public class BigIntPolynomial {
   private static final double LOG_10_2 = Math.log10(2.0D);
   BigInteger[] coeffs;

   BigIntPolynomial(int var1) {
      this.coeffs = new BigInteger[var1];

      for(int var2 = 0; var2 < var1; ++var2) {
         this.coeffs[var2] = Constants.BIGINT_ZERO;
      }

   }

   BigIntPolynomial(BigInteger[] var1) {
      this.coeffs = var1;
   }

   public BigIntPolynomial(IntegerPolynomial var1) {
      this.coeffs = new BigInteger[var1.coeffs.length];

      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         this.coeffs[var2] = BigInteger.valueOf((long)var1.coeffs[var2]);
      }

   }

   static BigIntPolynomial generateRandomSmall(int var0, int var1, int var2) {
      ArrayList var3 = new ArrayList();

      int var4;
      for(var4 = 0; var4 < var1; ++var4) {
         var3.add(Constants.BIGINT_ONE);
      }

      for(var4 = 0; var4 < var2; ++var4) {
         var3.add(BigInteger.valueOf(-1L));
      }

      while(var3.size() < var0) {
         var3.add(Constants.BIGINT_ZERO);
      }

      Collections.shuffle(var3, new SecureRandom());
      BigIntPolynomial var6 = new BigIntPolynomial(var0);

      for(int var5 = 0; var5 < var3.size(); ++var5) {
         var6.coeffs[var5] = (BigInteger)var3.get(var5);
      }

      return var6;
   }

   public BigIntPolynomial mult(BigIntPolynomial var1) {
      int var2 = this.coeffs.length;
      if (var1.coeffs.length != var2) {
         throw new IllegalArgumentException("Number of coefficients must be the same");
      } else {
         BigIntPolynomial var3 = this.multRecursive(var1);
         if (var3.coeffs.length > var2) {
            for(int var4 = var2; var4 < var3.coeffs.length; ++var4) {
               var3.coeffs[var4 - var2] = var3.coeffs[var4 - var2].add(var3.coeffs[var4]);
            }

            var3.coeffs = Arrays.copyOf(var3.coeffs, var2);
         }

         return var3;
      }
   }

   private BigIntPolynomial multRecursive(BigIntPolynomial var1) {
      BigInteger[] var2 = this.coeffs;
      BigInteger[] var3 = var1.coeffs;
      int var4 = var1.coeffs.length;
      if (var4 <= 1) {
         BigInteger[] var17 = Arrays.clone(this.coeffs);

         for(int var18 = 0; var18 < this.coeffs.length; ++var18) {
            var17[var18] = var17[var18].multiply(var1.coeffs[0]);
         }

         return new BigIntPolynomial(var17);
      } else {
         int var5 = var4 / 2;
         BigIntPolynomial var6 = new BigIntPolynomial(Arrays.copyOf(var2, var5));
         BigIntPolynomial var7 = new BigIntPolynomial(Arrays.copyOfRange(var2, var5, var4));
         BigIntPolynomial var8 = new BigIntPolynomial(Arrays.copyOf(var3, var5));
         BigIntPolynomial var9 = new BigIntPolynomial(Arrays.copyOfRange(var3, var5, var4));
         BigIntPolynomial var10 = (BigIntPolynomial)var6.clone();
         var10.add(var7);
         BigIntPolynomial var11 = (BigIntPolynomial)var8.clone();
         var11.add(var9);
         BigIntPolynomial var12 = var6.multRecursive(var8);
         BigIntPolynomial var13 = var7.multRecursive(var9);
         BigIntPolynomial var14 = var10.multRecursive(var11);
         var14.sub(var12);
         var14.sub(var13);
         BigIntPolynomial var15 = new BigIntPolynomial(2 * var4 - 1);

         int var16;
         for(var16 = 0; var16 < var12.coeffs.length; ++var16) {
            var15.coeffs[var16] = var12.coeffs[var16];
         }

         for(var16 = 0; var16 < var14.coeffs.length; ++var16) {
            var15.coeffs[var5 + var16] = var15.coeffs[var5 + var16].add(var14.coeffs[var16]);
         }

         for(var16 = 0; var16 < var13.coeffs.length; ++var16) {
            var15.coeffs[2 * var5 + var16] = var15.coeffs[2 * var5 + var16].add(var13.coeffs[var16]);
         }

         return var15;
      }
   }

   void add(BigIntPolynomial var1, BigInteger var2) {
      this.add(var1);
      this.mod(var2);
   }

   public void add(BigIntPolynomial var1) {
      int var2;
      if (var1.coeffs.length > this.coeffs.length) {
         var2 = this.coeffs.length;
         this.coeffs = Arrays.copyOf(this.coeffs, var1.coeffs.length);

         for(int var3 = var2; var3 < this.coeffs.length; ++var3) {
            this.coeffs[var3] = Constants.BIGINT_ZERO;
         }
      }

      for(var2 = 0; var2 < var1.coeffs.length; ++var2) {
         this.coeffs[var2] = this.coeffs[var2].add(var1.coeffs[var2]);
      }

   }

   public void sub(BigIntPolynomial var1) {
      int var2;
      if (var1.coeffs.length > this.coeffs.length) {
         var2 = this.coeffs.length;
         this.coeffs = Arrays.copyOf(this.coeffs, var1.coeffs.length);

         for(int var3 = var2; var3 < this.coeffs.length; ++var3) {
            this.coeffs[var3] = Constants.BIGINT_ZERO;
         }
      }

      for(var2 = 0; var2 < var1.coeffs.length; ++var2) {
         this.coeffs[var2] = this.coeffs[var2].subtract(var1.coeffs[var2]);
      }

   }

   public void mult(BigInteger var1) {
      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         this.coeffs[var2] = this.coeffs[var2].multiply(var1);
      }

   }

   void mult(int var1) {
      this.mult(BigInteger.valueOf((long)var1));
   }

   public void div(BigInteger var1) {
      BigInteger var2 = var1.add(Constants.BIGINT_ONE).divide(BigInteger.valueOf(2L));

      for(int var3 = 0; var3 < this.coeffs.length; ++var3) {
         this.coeffs[var3] = this.coeffs[var3].compareTo(Constants.BIGINT_ZERO) > 0 ? this.coeffs[var3].add(var2) : this.coeffs[var3].add(var2.negate());
         this.coeffs[var3] = this.coeffs[var3].divide(var1);
      }

   }

   public BigDecimalPolynomial div(BigDecimal var1, int var2) {
      BigInteger var3 = this.maxCoeffAbs();
      int var4 = (int)((double)var3.bitLength() * LOG_10_2) + 1;
      BigDecimal var5 = Constants.BIGDEC_ONE.divide(var1, var4 + var2 + 1, 6);
      BigDecimalPolynomial var6 = new BigDecimalPolynomial(this.coeffs.length);

      for(int var7 = 0; var7 < this.coeffs.length; ++var7) {
         var6.coeffs[var7] = (new BigDecimal(this.coeffs[var7])).multiply(var5).setScale(var2, 6);
      }

      return var6;
   }

   public int getMaxCoeffLength() {
      return (int)((double)this.maxCoeffAbs().bitLength() * LOG_10_2) + 1;
   }

   private BigInteger maxCoeffAbs() {
      BigInteger var1 = this.coeffs[0].abs();

      for(int var2 = 1; var2 < this.coeffs.length; ++var2) {
         BigInteger var3 = this.coeffs[var2].abs();
         if (var3.compareTo(var1) > 0) {
            var1 = var3;
         }
      }

      return var1;
   }

   public void mod(BigInteger var1) {
      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         this.coeffs[var2] = this.coeffs[var2].mod(var1);
      }

   }

   BigInteger sumCoeffs() {
      BigInteger var1 = Constants.BIGINT_ZERO;

      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         var1 = var1.add(this.coeffs[var2]);
      }

      return var1;
   }

   public Object clone() {
      return new BigIntPolynomial((BigInteger[])this.coeffs.clone());
   }

   public int hashCode() {
      boolean var1 = true;
      byte var2 = 1;
      int var3 = 31 * var2 + Arrays.hashCode(this.coeffs);
      return var3;
   }

   public boolean equals(Object var1) {
      if (this == var1) {
         return true;
      } else if (var1 == null) {
         return false;
      } else if (this.getClass() != var1.getClass()) {
         return false;
      } else {
         BigIntPolynomial var2 = (BigIntPolynomial)var1;
         return Arrays.areEqual(this.coeffs, var2.coeffs);
      }
   }

   public BigInteger[] getCoeffs() {
      return Arrays.clone(this.coeffs);
   }
}
