package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;

public final class DESKeyGenerator extends KeyGeneratorSpi {
   private SecureRandom random = null;

   protected void engineInit(SecureRandom var1) {
      this.random = var1;
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      throw new InvalidAlgorithmParameterException("DES key generation does not take any parameters");
   }

   protected void engineInit(int var1, SecureRandom var2) {
      if (var1 != 56) {
         throw new InvalidParameterException("Wrong keysize: must be equal to 56");
      } else {
         this.engineInit(var2);
      }
   }

   protected SecretKey engineGenerateKey() {
      DESKey var1 = null;
      if (this.random == null) {
         this.random = SunJCE.RANDOM;
      }

      try {
         byte[] var2 = new byte[8];

         do {
            this.random.nextBytes(var2);
            setParityBit(var2, 0);
         } while(DESKeySpec.isWeak(var2, 0));

         var1 = new DESKey(var2);
      } catch (InvalidKeyException var3) {
         ;
      }

      return var1;
   }

   static void setParityBit(byte[] var0, int var1) {
      if (var0 != null) {
         for(int var2 = 0; var2 < 8; ++var2) {
            int var3 = var0[var1] & 254;
            var3 |= Integer.bitCount(var3) & 1 ^ 1;
            var0[var1++] = (byte)var3;
         }

      }
   }
}
