package cn.gmssl.crypto.impl.sm2;

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

public class SM2ParameterSpec implements AlgorithmParameterSpec {
   private byte[] id = null;
   private PublicKey publicKey = null;

   public SM2ParameterSpec(byte[] var1, PublicKey var2) {
      this.publicKey = var2;
      this.id = var1;
   }

   public byte[] getId() {
      return this.id;
   }

   public PublicKey getPublicKey() {
      return this.publicKey;
   }
}
