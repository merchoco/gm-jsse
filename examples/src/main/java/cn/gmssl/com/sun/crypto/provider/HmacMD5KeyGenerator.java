package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class HmacMD5KeyGenerator extends KeyGeneratorSpi {
   private SecureRandom random = null;
   private int keysize = 64;

   protected void engineInit(SecureRandom var1) {
      this.random = var1;
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      throw new InvalidAlgorithmParameterException("HMAC-MD5 key generation does not take any parameters");
   }

   protected void engineInit(int var1, SecureRandom var2) {
      this.keysize = (var1 + 7) / 8;
      this.engineInit(var2);
   }

   protected SecretKey engineGenerateKey() {
      if (this.random == null) {
         this.random = SunJCE.RANDOM;
      }

      byte[] var1 = new byte[this.keysize];
      this.random.nextBytes(var1);
      return new SecretKeySpec(var1, "HmacMD5");
   }
}
