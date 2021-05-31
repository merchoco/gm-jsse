package org.bc.math.ntru.polynomial;

import java.math.BigInteger;

public class Resultant {
   public BigIntPolynomial rho;
   public BigInteger res;

   Resultant(BigIntPolynomial var1, BigInteger var2) {
      this.rho = var1;
      this.res = var2;
   }
}
