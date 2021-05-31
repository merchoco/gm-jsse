package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class AESKeyGenerator extends KeyGeneratorSpi {
   private SecureRandom random = null;
   private int keySize = 16;

   protected void engineInit(SecureRandom var1) {
      this.random = var1;
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      throw new InvalidAlgorithmParameterException("AES key generation does not take any parameters");
   }

   protected void engineInit(int var1, SecureRandom var2) {
      if (var1 % 8 == 0 && AESCrypt.isKeySizeValid(var1 / 8)) {
         this.keySize = var1 / 8;
         this.engineInit(var2);
      } else {
         throw new InvalidParameterException("Wrong keysize: must be equal to 128, 192 or 256");
      }
   }

   protected SecretKey engineGenerateKey() {
      SecretKeySpec var1 = null;
      if (this.random == null) {
         this.random = SunJCE.RANDOM;
      }

      byte[] var2 = new byte[this.keySize];
      this.random.nextBytes(var2);
      var1 = new SecretKeySpec(var2, "AES");
      return var1;
   }
}
