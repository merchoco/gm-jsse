package org.bc.crypto.params;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bc.math.ntru.polynomial.IntegerPolynomial;
import org.bc.math.ntru.polynomial.Polynomial;
import org.bc.math.ntru.polynomial.ProductFormPolynomial;
import org.bc.math.ntru.polynomial.SparseTernaryPolynomial;

public class NTRUEncryptionPrivateKeyParameters extends NTRUEncryptionKeyParameters {
   public Polynomial t;
   public IntegerPolynomial fp;
   public IntegerPolynomial h;

   public NTRUEncryptionPrivateKeyParameters(IntegerPolynomial var1, Polynomial var2, IntegerPolynomial var3, NTRUEncryptionParameters var4) {
      super(true, var4);
      this.h = var1;
      this.t = var2;
      this.fp = var3;
   }

   public NTRUEncryptionPrivateKeyParameters(byte[] var1, NTRUEncryptionParameters var2) throws IOException {
      this((InputStream)(new ByteArrayInputStream(var1)), var2);
   }

   public NTRUEncryptionPrivateKeyParameters(InputStream var1, NTRUEncryptionParameters var2) throws IOException {
      super(true, var2);
      if (var2.polyType == 1) {
         int var3 = var2.N;
         int var4 = var2.df1;
         int var5 = var2.df2;
         int var6 = var2.df3;
         int var7 = var2.fastFp ? var2.df3 : var2.df3 - 1;
         this.h = IntegerPolynomial.fromBinary(var1, var2.N, var2.q);
         this.t = ProductFormPolynomial.fromBinary(var1, var3, var4, var5, var6, var7);
      } else {
         this.h = IntegerPolynomial.fromBinary(var1, var2.N, var2.q);
         IntegerPolynomial var8 = IntegerPolynomial.fromBinary3Tight(var1, var2.N);
         this.t = (Polynomial)(var2.sparse ? new SparseTernaryPolynomial(var8) : new DenseTernaryPolynomial(var8));
      }

      this.init();
   }

   private void init() {
      if (this.params.fastFp) {
         this.fp = new IntegerPolynomial(this.params.N);
         this.fp.coeffs[0] = 1;
      } else {
         this.fp = this.t.toIntegerPolynomial().invertF3();
      }

   }

   public byte[] getEncoded() {
      byte[] var1 = this.h.toBinary(this.params.q);
      byte[] var2;
      if (this.t instanceof ProductFormPolynomial) {
         var2 = ((ProductFormPolynomial)this.t).toBinary();
      } else {
         var2 = this.t.toIntegerPolynomial().toBinary3Tight();
      }

      byte[] var3 = new byte[var1.length + var2.length];
      System.arraycopy(var1, 0, var3, 0, var1.length);
      System.arraycopy(var2, 0, var3, var1.length, var2.length);
      return var3;
   }

   public void writeTo(OutputStream var1) throws IOException {
      var1.write(this.getEncoded());
   }

   public int hashCode() {
      boolean var1 = true;
      byte var2 = 1;
      int var3 = 31 * var2 + (this.params == null ? 0 : this.params.hashCode());
      var3 = 31 * var3 + (this.t == null ? 0 : this.t.hashCode());
      var3 = 31 * var3 + (this.h == null ? 0 : this.h.hashCode());
      return var3;
   }

   public boolean equals(Object var1) {
      if (this == var1) {
         return true;
      } else if (var1 == null) {
         return false;
      } else if (!(var1 instanceof NTRUEncryptionPrivateKeyParameters)) {
         return false;
      } else {
         NTRUEncryptionPrivateKeyParameters var2 = (NTRUEncryptionPrivateKeyParameters)var1;
         if (this.params == null) {
            if (var2.params != null) {
               return false;
            }
         } else if (!this.params.equals(var2.params)) {
            return false;
         }

         if (this.t == null) {
            if (var2.t != null) {
               return false;
            }
         } else if (!this.t.equals(var2.t)) {
            return false;
         }

         return this.h.equals(var2.h);
      }
   }
}
