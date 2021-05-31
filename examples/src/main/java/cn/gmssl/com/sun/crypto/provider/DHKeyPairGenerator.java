package cn.gmssl.com.sun.crypto.provider;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import sun.security.provider.ParameterCache;

public final class DHKeyPairGenerator extends KeyPairGeneratorSpi {
   private DHParameterSpec params;
   private int pSize;
   private int lSize;
   private SecureRandom random;

   public DHKeyPairGenerator() {
      this.initialize(1024, (SecureRandom)null);
   }

   public void initialize(int var1, SecureRandom var2) {
      if (var1 >= 512 && var1 <= 1024 && var1 % 64 == 0) {
         this.pSize = var1;
         this.lSize = 0;
         this.random = var2;
         this.params = null;
      } else {
         throw new InvalidParameterException("Keysize must be multiple of 64, and can only range from 512 to 1024 (inclusive)");
      }
   }

   public void initialize(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof DHParameterSpec)) {
         throw new InvalidAlgorithmParameterException("Inappropriate parameter type");
      } else {
         this.params = (DHParameterSpec)var1;
         this.pSize = this.params.getP().bitLength();
         if (this.pSize >= 512 && this.pSize <= 1024 && this.pSize % 64 == 0) {
            this.lSize = this.params.getL();
            if (this.lSize != 0 && this.lSize > this.pSize) {
               throw new InvalidAlgorithmParameterException("Exponent size must not be larger than modulus size");
            } else {
               this.random = var2;
            }
         } else {
            throw new InvalidAlgorithmParameterException("Prime size must be multiple of 64, and can only range from 512 to 1024 (inclusive)");
         }
      }
   }

   public KeyPair generateKeyPair() {
      if (this.random == null) {
         this.random = SunJCE.RANDOM;
      }

      if (this.params == null) {
         try {
            this.params = ParameterCache.getDHParameterSpec(this.pSize, this.random);
         } catch (GeneralSecurityException var8) {
            throw new ProviderException(var8);
         }
      }

      BigInteger var1 = this.params.getP();
      BigInteger var2 = this.params.getG();
      if (this.lSize <= 0) {
         this.lSize = Math.max(384, this.pSize >> 1);
         this.lSize = Math.min(this.lSize, this.pSize);
      }

      BigInteger var4 = var1.subtract(BigInteger.valueOf(2L));

      BigInteger var3;
      do {
         do {
            var3 = new BigInteger(this.lSize, this.random);
         } while(var3.compareTo(BigInteger.ONE) < 0);
      } while(var3.compareTo(var4) > 0);

      BigInteger var5 = var2.modPow(var3, var1);
      DHPublicKey var6 = new DHPublicKey(var5, var1, var2, this.lSize);
      DHPrivateKey var7 = new DHPrivateKey(var3, var1, var2, this.lSize);
      return new KeyPair(var6, var7);
   }
}
