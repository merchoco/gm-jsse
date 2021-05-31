package cn.gmssl.com.sun.crypto.provider;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

public final class DHParameterGenerator extends AlgorithmParameterGeneratorSpi {
   private int primeSize = 1024;
   private int exponentSize = 0;
   private SecureRandom random = null;

   protected void engineInit(int var1, SecureRandom var2) {
      if (var1 >= 512 && var1 <= 1024 && var1 % 64 == 0) {
         this.primeSize = var1;
         this.random = var2;
      } else {
         throw new InvalidParameterException("Keysize must be multiple of 64, and can only range from 512 to 1024 (inclusive)");
      }
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof DHGenParameterSpec)) {
         throw new InvalidAlgorithmParameterException("Inappropriate parameter type");
      } else {
         DHGenParameterSpec var3 = (DHGenParameterSpec)var1;
         this.primeSize = var3.getPrimeSize();
         if (this.primeSize >= 512 && this.primeSize <= 1024 && this.primeSize % 64 == 0) {
            this.exponentSize = var3.getExponentSize();
            if (this.exponentSize <= 0) {
               throw new InvalidAlgorithmParameterException("Exponent size must be greater than zero");
            } else if (this.exponentSize >= this.primeSize) {
               throw new InvalidAlgorithmParameterException("Exponent size must be less than modulus size");
            }
         } else {
            throw new InvalidAlgorithmParameterException("Modulus size must be multiple of 64, and can only range from 512 to 1024 (inclusive)");
         }
      }
   }

   protected AlgorithmParameters engineGenerateParameters() {
      AlgorithmParameters var1 = null;
      if (this.exponentSize == 0) {
         this.exponentSize = this.primeSize - 1;
      }

      if (this.random == null) {
         this.random = SunJCE.RANDOM;
      }

      try {
         AlgorithmParameterGenerator var2 = AlgorithmParameterGenerator.getInstance("DSA");
         var2.init(this.primeSize, this.random);
         var1 = var2.generateParameters();
         DSAParameterSpec var3 = (DSAParameterSpec)var1.getParameterSpec(DSAParameterSpec.class);
         DHParameterSpec var4;
         if (this.exponentSize > 0) {
            var4 = new DHParameterSpec(var3.getP(), var3.getG(), this.exponentSize);
         } else {
            var4 = new DHParameterSpec(var3.getP(), var3.getG());
         }

         var1 = AlgorithmParameters.getInstance("DH", "SunJCE");
         var1.init(var4);
         return var1;
      } catch (InvalidParameterSpecException var5) {
         throw new RuntimeException(var5.getMessage());
      } catch (NoSuchAlgorithmException var6) {
         throw new RuntimeException(var6.getMessage());
      } catch (NoSuchProviderException var7) {
         throw new RuntimeException(var7.getMessage());
      }
   }
}
