package org.bc.crypto.params;

import java.math.BigInteger;

public class DSAPublicKeyParameters extends DSAKeyParameters {
   private BigInteger y;

   public DSAPublicKeyParameters(BigInteger var1, DSAParameters var2) {
      super(false, var2);
      this.y = var1;
   }

   public BigInteger getY() {
      return this.y;
   }
}
