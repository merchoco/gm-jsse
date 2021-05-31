package org.bc.crypto.params;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bc.math.ntru.polynomial.IntegerPolynomial;

public class NTRUSigningPublicKeyParameters extends AsymmetricKeyParameter {
   private NTRUSigningParameters params;
   public IntegerPolynomial h;

   public NTRUSigningPublicKeyParameters(IntegerPolynomial var1, NTRUSigningParameters var2) {
      super(false);
      this.h = var1;
      this.params = var2;
   }

   public NTRUSigningPublicKeyParameters(byte[] var1, NTRUSigningParameters var2) {
      super(false);
      this.h = IntegerPolynomial.fromBinary(var1, var2.N, var2.q);
      this.params = var2;
   }

   public NTRUSigningPublicKeyParameters(InputStream var1, NTRUSigningParameters var2) throws IOException {
      super(false);
      this.h = IntegerPolynomial.fromBinary(var1, var2.N, var2.q);
      this.params = var2;
   }

   public byte[] getEncoded() {
      return this.h.toBinary(this.params.q);
   }

   public void writeTo(OutputStream var1) throws IOException {
      var1.write(this.getEncoded());
   }

   public int hashCode() {
      boolean var1 = true;
      byte var2 = 1;
      int var3 = 31 * var2 + (this.h == null ? 0 : this.h.hashCode());
      var3 = 31 * var3 + (this.params == null ? 0 : this.params.hashCode());
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
         NTRUSigningPublicKeyParameters var2 = (NTRUSigningPublicKeyParameters)var1;
         if (this.h == null) {
            if (var2.h != null) {
               return false;
            }
         } else if (!this.h.equals(var2.h)) {
            return false;
         }

         if (this.params == null) {
            if (var2.params != null) {
               return false;
            }
         } else if (!this.params.equals(var2.params)) {
            return false;
         }

         return true;
      }
   }
}
