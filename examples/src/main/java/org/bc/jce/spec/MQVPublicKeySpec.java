package org.bc.jce.spec;

import java.security.PublicKey;
import java.security.spec.KeySpec;
import org.bc.jce.interfaces.MQVPublicKey;

public class MQVPublicKeySpec implements KeySpec, MQVPublicKey {
   private PublicKey staticKey;
   private PublicKey ephemeralKey;

   public MQVPublicKeySpec(PublicKey var1, PublicKey var2) {
      this.staticKey = var1;
      this.ephemeralKey = var2;
   }

   public PublicKey getStaticKey() {
      return this.staticKey;
   }

   public PublicKey getEphemeralKey() {
      return this.ephemeralKey;
   }

   public String getAlgorithm() {
      return "ECMQV";
   }

   public String getFormat() {
      return null;
   }

   public byte[] getEncoded() {
      return null;
   }
}
