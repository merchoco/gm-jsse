package org.bc.crypto.params;

import org.bc.crypto.CipherParameters;

public class MQVPrivateParameters implements CipherParameters {
   private ECPrivateKeyParameters staticPrivateKey;
   private ECPrivateKeyParameters ephemeralPrivateKey;
   private ECPublicKeyParameters ephemeralPublicKey;

   public MQVPrivateParameters(ECPrivateKeyParameters var1, ECPrivateKeyParameters var2) {
      this(var1, var2, (ECPublicKeyParameters)null);
   }

   public MQVPrivateParameters(ECPrivateKeyParameters var1, ECPrivateKeyParameters var2, ECPublicKeyParameters var3) {
      this.staticPrivateKey = var1;
      this.ephemeralPrivateKey = var2;
      this.ephemeralPublicKey = var3;
   }

   public ECPrivateKeyParameters getStaticPrivateKey() {
      return this.staticPrivateKey;
   }

   public ECPrivateKeyParameters getEphemeralPrivateKey() {
      return this.ephemeralPrivateKey;
   }

   public ECPublicKeyParameters getEphemeralPublicKey() {
      return this.ephemeralPublicKey;
   }
}
