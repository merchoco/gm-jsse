package org.bc.jcajce.provider.asymmetric.dsa;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import org.bc.crypto.generators.DSAParametersGenerator;
import org.bc.crypto.params.DSAParameters;
import org.bc.jce.provider.BouncyCastleProvider;

public class AlgorithmParameterGeneratorSpi extends java.security.AlgorithmParameterGeneratorSpi {
   protected SecureRandom random;
   protected int strength = 1024;

   protected void engineInit(int var1, SecureRandom var2) {
      if (var1 >= 512 && var1 <= 1024 && var1 % 64 == 0) {
         this.strength = var1;
         this.random = var2;
      } else {
         throw new InvalidParameterException("strength must be from 512 - 1024 and a multiple of 64");
      }
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DSA parameter generation.");
   }

   protected AlgorithmParameters engineGenerateParameters() {
      DSAParametersGenerator var1 = new DSAParametersGenerator();
      if (this.random != null) {
         var1.init(this.strength, 20, this.random);
      } else {
         var1.init(this.strength, 20, new SecureRandom());
      }

      DSAParameters var2 = var1.generateParameters();

      try {
         AlgorithmParameters var3 = AlgorithmParameters.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
         var3.init(new DSAParameterSpec(var2.getP(), var2.getQ(), var2.getG()));
         return var3;
      } catch (Exception var5) {
         throw new RuntimeException(var5.getMessage());
      }
   }
}
