package org.bc.math.ntru.polynomial;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import org.bc.util.Arrays;

public class ProductFormPolynomial implements Polynomial {
   private SparseTernaryPolynomial f1;
   private SparseTernaryPolynomial f2;
   private SparseTernaryPolynomial f3;

   public ProductFormPolynomial(SparseTernaryPolynomial var1, SparseTernaryPolynomial var2, SparseTernaryPolynomial var3) {
      this.f1 = var1;
      this.f2 = var2;
      this.f3 = var3;
   }

   public static ProductFormPolynomial generateRandom(int var0, int var1, int var2, int var3, int var4, SecureRandom var5) {
      SparseTernaryPolynomial var6 = SparseTernaryPolynomial.generateRandom(var0, var1, var1, var5);
      SparseTernaryPolynomial var7 = SparseTernaryPolynomial.generateRandom(var0, var2, var2, var5);
      SparseTernaryPolynomial var8 = SparseTernaryPolynomial.generateRandom(var0, var3, var4, var5);
      return new ProductFormPolynomial(var6, var7, var8);
   }

   public static ProductFormPolynomial fromBinary(byte[] var0, int var1, int var2, int var3, int var4, int var5) throws IOException {
      return fromBinary((InputStream)(new ByteArrayInputStream(var0)), var1, var2, var3, var4, var5);
   }

   public static ProductFormPolynomial fromBinary(InputStream var0, int var1, int var2, int var3, int var4, int var5) throws IOException {
      SparseTernaryPolynomial var6 = SparseTernaryPolynomial.fromBinary(var0, var1, var2, var2);
      SparseTernaryPolynomial var7 = SparseTernaryPolynomial.fromBinary(var0, var1, var3, var3);
      SparseTernaryPolynomial var8 = SparseTernaryPolynomial.fromBinary(var0, var1, var4, var5);
      return new ProductFormPolynomial(var6, var7, var8);
   }

   public byte[] toBinary() {
      byte[] var1 = this.f1.toBinary();
      byte[] var2 = this.f2.toBinary();
      byte[] var3 = this.f3.toBinary();
      byte[] var4 = Arrays.copyOf(var1, var1.length + var2.length + var3.length);
      System.arraycopy(var2, 0, var4, var1.length, var2.length);
      System.arraycopy(var3, 0, var4, var1.length + var2.length, var3.length);
      return var4;
   }

   public IntegerPolynomial mult(IntegerPolynomial var1) {
      IntegerPolynomial var2 = this.f1.mult(var1);
      var2 = this.f2.mult(var2);
      var2.add(this.f3.mult(var1));
      return var2;
   }

   public BigIntPolynomial mult(BigIntPolynomial var1) {
      BigIntPolynomial var2 = this.f1.mult(var1);
      var2 = this.f2.mult(var2);
      var2.add(this.f3.mult(var1));
      return var2;
   }

   public IntegerPolynomial toIntegerPolynomial() {
      IntegerPolynomial var1 = this.f1.mult(this.f2.toIntegerPolynomial());
      var1.add(this.f3.toIntegerPolynomial());
      return var1;
   }

   public IntegerPolynomial mult(IntegerPolynomial var1, int var2) {
      IntegerPolynomial var3 = this.mult(var1);
      var3.mod(var2);
      return var3;
   }

   public int hashCode() {
      boolean var1 = true;
      byte var2 = 1;
      int var3 = 31 * var2 + (this.f1 == null ? 0 : this.f1.hashCode());
      var3 = 31 * var3 + (this.f2 == null ? 0 : this.f2.hashCode());
      var3 = 31 * var3 + (this.f3 == null ? 0 : this.f3.hashCode());
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
         ProductFormPolynomial var2 = (ProductFormPolynomial)var1;
         if (this.f1 == null) {
            if (var2.f1 != null) {
               return false;
            }
         } else if (!this.f1.equals(var2.f1)) {
            return false;
         }

         if (this.f2 == null) {
            if (var2.f2 != null) {
               return false;
            }
         } else if (!this.f2.equals(var2.f2)) {
            return false;
         }

         if (this.f3 == null) {
            if (var2.f3 != null) {
               return false;
            }
         } else if (!this.f3.equals(var2.f3)) {
            return false;
         }

         return true;
      }
   }
}
