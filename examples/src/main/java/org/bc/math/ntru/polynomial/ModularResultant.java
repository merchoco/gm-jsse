package org.bc.math.ntru.polynomial;

import java.math.BigInteger;
import org.bc.math.ntru.euclid.BigIntEuclidean;

public class ModularResultant extends Resultant {
   BigInteger modulus;

   ModularResultant(BigIntPolynomial var1, BigInteger var2, BigInteger var3) {
      super(var1, var2);
      this.modulus = var3;
   }

   static ModularResultant combineRho(ModularResultant var0, ModularResultant var1) {
      BigInteger var2 = var0.modulus;
      BigInteger var3 = var1.modulus;
      BigInteger var4 = var2.multiply(var3);
      BigIntEuclidean var5 = BigIntEuclidean.calculate(var3, var2);
      BigIntPolynomial var6 = (BigIntPolynomial)var0.rho.clone();
      var6.mult(var5.x.multiply(var3));
      BigIntPolynomial var7 = (BigIntPolynomial)var1.rho.clone();
      var7.mult(var5.y.multiply(var2));
      var6.add(var7);
      var6.mod(var4);
      return new ModularResultant(var6, (BigInteger)null, var4);
   }
}
