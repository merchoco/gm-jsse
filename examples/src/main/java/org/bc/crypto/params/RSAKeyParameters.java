package org.bc.crypto.params;

import java.math.BigInteger;

public class RSAKeyParameters extends AsymmetricKeyParameter {
   private BigInteger modulus;
   private BigInteger exponent;

   public RSAKeyParameters(boolean var1, BigInteger var2, BigInteger var3) {
      super(var1);
      this.modulus = var2;
      this.exponent = var3;
   }

   public BigInteger getModulus() {
      return this.modulus;
   }

   public BigInteger getExponent() {
      return this.exponent;
   }
}
