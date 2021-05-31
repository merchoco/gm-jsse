package org.bc.crypto.generators;

import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.EphemeralKeyPair;
import org.bc.crypto.KeyEncoder;

public class EphemeralKeyPairGenerator {
   private AsymmetricCipherKeyPairGenerator gen;
   private KeyEncoder keyEncoder;

   public EphemeralKeyPairGenerator(AsymmetricCipherKeyPairGenerator var1, KeyEncoder var2) {
      this.gen = var1;
      this.keyEncoder = var2;
   }

   public EphemeralKeyPair generate() {
      AsymmetricCipherKeyPair var1 = this.gen.generateKeyPair();
      return new EphemeralKeyPair(var1, this.keyEncoder);
   }
}
