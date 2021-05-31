package org.bc.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.crypto.params.RSAPrivateCrtKeyParameters;
import org.bc.util.BigIntegers;

public class RSABlindedEngine implements AsymmetricBlockCipher {
   private static BigInteger ONE = BigInteger.valueOf(1L);
   private RSACoreEngine core = new RSACoreEngine();
   private RSAKeyParameters key;
   private SecureRandom random;

   public void init(boolean var1, CipherParameters var2) {
      this.core.init(var1, var2);
      if (var2 instanceof ParametersWithRandom) {
         ParametersWithRandom var3 = (ParametersWithRandom)var2;
         this.key = (RSAKeyParameters)var3.getParameters();
         this.random = var3.getRandom();
      } else {
         this.key = (RSAKeyParameters)var2;
         this.random = new SecureRandom();
      }

   }

   public int getInputBlockSize() {
      return this.core.getInputBlockSize();
   }

   public int getOutputBlockSize() {
      return this.core.getOutputBlockSize();
   }

   public byte[] processBlock(byte[] var1, int var2, int var3) {
      if (this.key == null) {
         throw new IllegalStateException("RSA engine not initialised");
      } else {
         BigInteger var4 = this.core.convertInput(var1, var2, var3);
         BigInteger var5;
         if (this.key instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters var6 = (RSAPrivateCrtKeyParameters)this.key;
            BigInteger var7 = var6.getPublicExponent();
            if (var7 != null) {
               BigInteger var8 = var6.getModulus();
               BigInteger var9 = BigIntegers.createRandomInRange(ONE, var8.subtract(ONE), this.random);
               BigInteger var10 = var9.modPow(var7, var8).multiply(var4).mod(var8);
               BigInteger var11 = this.core.processBlock(var10);
               BigInteger var12 = var9.modInverse(var8);
               var5 = var11.multiply(var12).mod(var8);
            } else {
               var5 = this.core.processBlock(var4);
            }
         } else {
            var5 = this.core.processBlock(var4);
         }

         return this.core.convertOutput(var5);
      }
   }
}
