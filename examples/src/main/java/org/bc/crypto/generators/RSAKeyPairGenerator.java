package org.bc.crypto.generators;

import java.math.BigInteger;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.params.RSAKeyGenerationParameters;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.crypto.params.RSAPrivateCrtKeyParameters;

public class RSAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
   private static final BigInteger ONE = BigInteger.valueOf(1L);
   private RSAKeyGenerationParameters param;

   public void init(KeyGenerationParameters var1) {
      this.param = (RSAKeyGenerationParameters)var1;
   }

   public AsymmetricCipherKeyPair generateKeyPair() {
      int var9 = this.param.getStrength();
      int var10 = (var9 + 1) / 2;
      int var11 = var9 - var10;
      int var12 = var9 / 3;
      BigInteger var5 = this.param.getPublicExponent();

      BigInteger var1;
      do {
         while(true) {
            var1 = new BigInteger(var10, 1, this.param.getRandom());
            if (var1.mod(var5).equals(ONE)) {
               continue;
            }
            break;
         }
      } while(!var1.isProbablePrime(this.param.getCertainty()) || !var5.gcd(var1.subtract(ONE)).equals(ONE));

      while(true) {
         while(true) {
            BigInteger var2 = new BigInteger(var11, 1, this.param.getRandom());
            if (var2.subtract(var1).abs().bitLength() >= var12 && !var2.mod(var5).equals(ONE) && var2.isProbablePrime(this.param.getCertainty()) && var5.gcd(var2.subtract(ONE)).equals(ONE)) {
               BigInteger var3 = var1.multiply(var2);
               if (var3.bitLength() == this.param.getStrength()) {
                  BigInteger var8;
                  if (var1.compareTo(var2) < 0) {
                     var8 = var1;
                     var1 = var2;
                     var2 = var8;
                  }

                  BigInteger var6 = var1.subtract(ONE);
                  BigInteger var7 = var2.subtract(ONE);
                  var8 = var6.multiply(var7);
                  BigInteger var4 = var5.modInverse(var8);
                  BigInteger var13 = var4.remainder(var6);
                  BigInteger var14 = var4.remainder(var7);
                  BigInteger var15 = var2.modInverse(var1);
                  return new AsymmetricCipherKeyPair(new RSAKeyParameters(false, var3, var5), new RSAPrivateCrtKeyParameters(var3, var5, var4, var1, var2, var13, var14, var15));
               }

               var1 = var1.max(var2);
            }
         }
      }
   }
}
