package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class BlowfishKeyGenerator extends KeyGeneratorSpi {
   private SecureRandom random = null;
   private int keysize = 16;

   protected void engineInit(SecureRandom var1) {
      this.random = var1;
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      throw new InvalidAlgorithmParameterException("Blowfish key generation does not take any parameters");
   }

   protected void engineInit(int var1, SecureRandom var2) {
      if (var1 % 8 == 0 && var1 >= 32 && var1 <= 448) {
         this.keysize = var1 / 8;
         this.engineInit(var2);
      } else {
         throw new InvalidParameterException("Keysize must be multiple of 8, and can only range from 32 to 448 (inclusive)");
      }
   }

   protected SecretKey engineGenerateKey() {
      if (this.random == null) {
         this.random = SunJCE.RANDOM;
      }

      byte[] var1 = new byte[this.keysize];
      this.random.nextBytes(var1);
      return new SecretKeySpec(var1, "Blowfish");
   }
}
