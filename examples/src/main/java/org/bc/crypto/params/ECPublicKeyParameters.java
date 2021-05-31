package org.bc.crypto.params;

import org.bc.math.ec.ECPoint;

public class ECPublicKeyParameters extends ECKeyParameters {
   ECPoint Q;

   public ECPublicKeyParameters(ECPoint var1, ECDomainParameters var2) {
      super(false, var2);
      this.Q = var1;
   }

   public ECPoint getQ() {
      return this.Q;
   }
}
