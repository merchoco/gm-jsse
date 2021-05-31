package org.bc.crypto.params;

import org.bc.crypto.CipherParameters;

public class MQVPublicParameters implements CipherParameters {
   private ECPublicKeyParameters staticPublicKey;
   private ECPublicKeyParameters ephemeralPublicKey;

   public MQVPublicParameters(ECPublicKeyParameters var1, ECPublicKeyParameters var2) {
      this.staticPublicKey = var1;
      this.ephemeralPublicKey = var2;
   }

   public ECPublicKeyParameters getStaticPublicKey() {
      return this.staticPublicKey;
   }

   public ECPublicKeyParameters getEphemeralPublicKey() {
      return this.ephemeralPublicKey;
   }
}
