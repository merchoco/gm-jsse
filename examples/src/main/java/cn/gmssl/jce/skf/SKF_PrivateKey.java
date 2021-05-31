package cn.gmssl.jce.skf;

import java.security.InvalidKeyException;
import java.security.PrivateKey;

public class SKF_PrivateKey implements PrivateKey {
   private static final long serialVersionUID = 4165752956339128733L;
   private ICryptoProvider cryptoProvider = null;
   private int sig = 0;

   public SKF_PrivateKey(ICryptoProvider var1, int var2) {
      this.cryptoProvider = var1;
      this.sig = var2;
   }

   public String getAlgorithm() {
      return "SM2";
   }

   public String getFormat() {
      return null;
   }

   public byte[] getEncoded() {
      return null;
   }

   public int getKeyLength() throws InvalidKeyException {
      return 32;
   }

   public ICryptoProvider getCryptoProvider() {
      return this.cryptoProvider;
   }

   public String toString() {
      return "SM2 Pri(sig=" + this.sig + ")";
   }
}
