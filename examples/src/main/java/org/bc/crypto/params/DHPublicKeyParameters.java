package org.bc.crypto.params;

import java.math.BigInteger;

public class DHPublicKeyParameters extends DHKeyParameters {
   private BigInteger y;

   public DHPublicKeyParameters(BigInteger var1, DHParameters var2) {
      super(false, var2);
      this.y = var1;
   }

   public BigInteger getY() {
      return this.y;
   }

   public int hashCode() {
      return this.y.hashCode() ^ super.hashCode();
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof DHPublicKeyParameters)) {
         return false;
      } else {
         DHPublicKeyParameters var2 = (DHPublicKeyParameters)var1;
         return var2.getY().equals(this.y) && super.equals(var1);
      }
   }
}
