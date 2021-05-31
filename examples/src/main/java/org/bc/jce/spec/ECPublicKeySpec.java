package org.bc.jce.spec;

import org.bc.math.ec.ECPoint;

public class ECPublicKeySpec extends ECKeySpec {
   private ECPoint q;

   public ECPublicKeySpec(ECPoint var1, ECParameterSpec var2) {
      super(var2);
      this.q = var1;
   }

   public ECPoint getQ() {
      return this.q;
   }
}
