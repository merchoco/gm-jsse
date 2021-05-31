package org.bc.jcajce.provider.asymmetric.dsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.generators.DSAKeyPairGenerator;
import org.bc.crypto.generators.DSAParametersGenerator;
import org.bc.crypto.params.DSAKeyGenerationParameters;
import org.bc.crypto.params.DSAParameters;
import org.bc.crypto.params.DSAPrivateKeyParameters;
import org.bc.crypto.params.DSAPublicKeyParameters;

public class KeyPairGeneratorSpi extends KeyPairGenerator {
   DSAKeyGenerationParameters param;
   DSAKeyPairGenerator engine = new DSAKeyPairGenerator();
   int strength = 1024;
   int certainty = 20;
   SecureRandom random = new SecureRandom();
   boolean initialised = false;

   public KeyPairGeneratorSpi() {
      super("DSA");
   }

   public void initialize(int var1, SecureRandom var2) {
      if (var1 >= 512 && var1 <= 1024 && var1 % 64 == 0) {
         this.strength = var1;
         this.random = var2;
      } else {
         throw new InvalidParameterException("strength must be from 512 - 1024 and a multiple of 64");
      }
   }

   public void initialize(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof DSAParameterSpec)) {
         throw new InvalidAlgorithmParameterException("parameter object not a DSAParameterSpec");
      } else {
         DSAParameterSpec var3 = (DSAParameterSpec)var1;
         this.param = new DSAKeyGenerationParameters(var2, new DSAParameters(var3.getP(), var3.getQ(), var3.getG()));
         this.engine.init(this.param);
         this.initialised = true;
      }
   }

   public KeyPair generateKeyPair() {
      if (!this.initialised) {
         DSAParametersGenerator var1 = new DSAParametersGenerator();
         var1.init(this.strength, this.certainty, this.random);
         this.param = new DSAKeyGenerationParameters(this.random, var1.generateParameters());
         this.engine.init(this.param);
         this.initialised = true;
      }

      AsymmetricCipherKeyPair var4 = this.engine.generateKeyPair();
      DSAPublicKeyParameters var2 = (DSAPublicKeyParameters)var4.getPublic();
      DSAPrivateKeyParameters var3 = (DSAPrivateKeyParameters)var4.getPrivate();
      return new KeyPair(new BCDSAPublicKey(var2), new BCDSAPrivateKey(var3));
   }
}
