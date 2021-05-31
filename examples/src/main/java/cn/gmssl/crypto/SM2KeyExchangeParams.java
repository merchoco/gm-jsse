package cn.gmssl.crypto;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

public class SM2KeyExchangeParams implements AlgorithmParameterSpec {
   private PublicKey publicKey = null;
   private PublicKey peerPublicKey = null;
   private BigInteger random = null;
   private byte[] idLocal = null;
   private byte[] idRemote = null;
   private int keyLength = 0;
   boolean active = false;

   public SM2KeyExchangeParams(PublicKey var1, PublicKey var2, BigInteger var3, byte[] var4, byte[] var5, int var6, boolean var7) {
      this.publicKey = var1;
      this.peerPublicKey = var2;
      this.random = var3;
      this.idLocal = var4;
      this.idRemote = var5;
      this.active = var7;
      this.keyLength = var6;
   }

   public PublicKey getPublicKey() {
      return this.publicKey;
   }

   public PublicKey getPeerPublicKey() {
      return this.peerPublicKey;
   }

   public BigInteger getRandom() {
      return this.random;
   }

   public boolean isActive() {
      return this.active;
   }

   public byte[] getIdLocal() {
      return this.idLocal;
   }

   public byte[] getIdRemote() {
      return this.idRemote;
   }

   public int getKeyLength() {
      return this.keyLength;
   }
}
