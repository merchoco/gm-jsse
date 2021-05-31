package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

public final class DESedeKeyGenerator extends KeyGeneratorSpi {
   private SecureRandom random = null;
   private int keysize = 168;

   protected void engineInit(SecureRandom var1) {
      this.random = var1;
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      throw new InvalidAlgorithmParameterException("Triple DES key generation does not take any parameters");
   }

   protected void engineInit(int var1, SecureRandom var2) {
      if (var1 != 112 && var1 != 168) {
         throw new InvalidParameterException("Wrong keysize: must be equal to 112 or 168");
      } else {
         this.keysize = var1;
         this.engineInit(var2);
      }
   }

   protected SecretKey engineGenerateKey() {
      if (this.random == null) {
         this.random = SunJCE.RANDOM;
      }

      byte[] var1 = new byte[24];
      if (this.keysize == 168) {
         this.random.nextBytes(var1);
         DESKeyGenerator.setParityBit(var1, 0);
         DESKeyGenerator.setParityBit(var1, 8);
         DESKeyGenerator.setParityBit(var1, 16);
      } else {
         byte[] var2 = new byte[16];
         this.random.nextBytes(var2);
         DESKeyGenerator.setParityBit(var2, 0);
         DESKeyGenerator.setParityBit(var2, 8);
         System.arraycopy(var2, 0, var1, 0, var2.length);
         System.arraycopy(var2, 0, var1, 16, 8);
         Arrays.fill(var2, (byte)0);
      }

      DESedeKey var5 = null;

      try {
         var5 = new DESedeKey(var1);
      } catch (InvalidKeyException var4) {
         throw new RuntimeException(var4.getMessage());
      }

      Arrays.fill(var1, (byte)0);
      return var5;
   }
}
