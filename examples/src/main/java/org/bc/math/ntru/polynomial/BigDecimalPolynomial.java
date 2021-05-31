package org.bc.math.ntru.polynomial;

import java.math.BigDecimal;

public class BigDecimalPolynomial {
   private static final BigDecimal ZERO = new BigDecimal("0");
   private static final BigDecimal ONE_HALF = new BigDecimal("0.5");
   BigDecimal[] coeffs;

   BigDecimalPolynomial(int var1) {
      this.coeffs = new BigDecimal[var1];

      for(int var2 = 0; var2 < var1; ++var2) {
         this.coeffs[var2] = ZERO;
      }

   }

   BigDecimalPolynomial(BigDecimal[] var1) {
      this.coeffs = var1;
   }

   public BigDecimalPolynomial(BigIntPolynomial var1) {
      int var2 = var1.coeffs.length;
      this.coeffs = new BigDecimal[var2];

      for(int var3 = 0; var3 < var2; ++var3) {
         this.coeffs[var3] = new BigDecimal(var1.coeffs[var3]);
      }

   }

   public void halve() {
      for(int var1 = 0; var1 < this.coeffs.length; ++var1) {
         this.coeffs[var1] = this.coeffs[var1].multiply(ONE_HALF);
      }

   }

   public BigDecimalPolynomial mult(BigIntPolynomial var1) {
      return this.mult(new BigDecimalPolynomial(var1));
   }

   public BigDecimalPolynomial mult(BigDecimalPolynomial var1) {
      int var2 = this.coeffs.length;
      if (var1.coeffs.length != var2) {
         throw new IllegalArgumentException("Number of coefficients must be the same");
      } else {
         BigDecimalPolynomial var3 = this.multRecursive(var1);
         if (var3.coeffs.length > var2) {
            for(int var4 = var2; var4 < var3.coeffs.length; ++var4) {
               var3.coeffs[var4 - var2] = var3.coeffs[var4 - var2].add(var3.coeffs[var4]);
            }

            var3.coeffs = this.copyOf(var3.coeffs, var2);
         }

         return var3;
      }
   }

   private BigDecimalPolynomial multRecursive(BigDecimalPolynomial var1) {
      BigDecimal[] var2 = this.coeffs;
      BigDecimal[] var3 = var1.coeffs;
      int var4 = var1.coeffs.length;
      if (var4 <= 1) {
         BigDecimal[] var17 = (BigDecimal[])this.coeffs.clone();

         for(int var18 = 0; var18 < this.coeffs.length; ++var18) {
            var17[var18] = var17[var18].multiply(var1.coeffs[0]);
         }

         return new BigDecimalPolynomial(var17);
      } else {
         int var5 = var4 / 2;
         BigDecimalPolynomial var6 = new BigDecimalPolynomial(this.copyOf(var2, var5));
         BigDecimalPolynomial var7 = new BigDecimalPolynomial(this.copyOfRange(var2, var5, var4));
         BigDecimalPolynomial var8 = new BigDecimalPolynomial(this.copyOf(var3, var5));
         BigDecimalPolynomial var9 = new BigDecimalPolynomial(this.copyOfRange(var3, var5, var4));
         BigDecimalPolynomial var10 = (BigDecimalPolynomial)var6.clone();
         var10.add(var7);
         BigDecimalPolynomial var11 = (BigDecimalPolynomial)var8.clone();
         var11.add(var9);
         BigDecimalPolynomial var12 = var6.multRecursive(var8);
         BigDecimalPolynomial var13 = var7.multRecursive(var9);
         BigDecimalPolynomial var14 = var10.multRecursive(var11);
         var14.sub(var12);
         var14.sub(var13);
         BigDecimalPolynomial var15 = new BigDecimalPolynomial(2 * var4 - 1);

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

   public void add(BigDecimalPolynomial var1) {
      int var2;
      if (var1.coeffs.length > this.coeffs.length) {
         var2 = this.coeffs.length;
         this.coeffs = this.copyOf(this.coeffs, var1.coeffs.length);

         for(int var3 = var2; var3 < this.coeffs.length; ++var3) {
            this.coeffs[var3] = ZERO;
         }
      }

      for(var2 = 0; var2 < var1.coeffs.length; ++var2) {
         this.coeffs[var2] = this.coeffs[var2].add(var1.coeffs[var2]);
      }

   }

   void sub(BigDecimalPolynomial var1) {
      int var2;
      if (var1.coeffs.length > this.coeffs.length) {
         var2 = this.coeffs.length;
         this.coeffs = this.copyOf(this.coeffs, var1.coeffs.length);

         for(int var3 = var2; var3 < this.coeffs.length; ++var3) {
            this.coeffs[var3] = ZERO;
         }
      }

      for(var2 = 0; var2 < var1.coeffs.length; ++var2) {
         this.coeffs[var2] = this.coeffs[var2].subtract(var1.coeffs[var2]);
      }

   }

   public BigIntPolynomial round() {
      int var1 = this.coeffs.length;
      BigIntPolynomial var2 = new BigIntPolynomial(var1);

      for(int var3 = 0; var3 < var1; ++var3) {
         var2.coeffs[var3] = this.coeffs[var3].setScale(0, 6).toBigInteger();
      }

      return var2;
   }

   public Object clone() {
      return new BigDecimalPolynomial((BigDecimal[])this.coeffs.clone());
   }

   private BigDecimal[] copyOf(BigDecimal[] var1, int var2) {
      BigDecimal[] var3 = new BigDecimal[var2];
      System.arraycopy(var1, 0, var3, 0, var1.length < var2 ? var1.length : var2);
      return var3;
   }

   private BigDecimal[] copyOfRange(BigDecimal[] var1, int var2, int var3) {
      int var4 = var3 - var2;
      BigDecimal[] var5 = new BigDecimal[var3 - var2];
      System.arraycopy(var1, var2, var5, 0, var1.length - var2 < var4 ? var1.length - var2 : var4);
      return var5;
   }

   public BigDecimal[] getCoeffs() {
      BigDecimal[] var1 = new BigDecimal[this.coeffs.length];
      System.arraycopy(this.coeffs, 0, var1, 0, this.coeffs.length);
      return var1;
   }
}
