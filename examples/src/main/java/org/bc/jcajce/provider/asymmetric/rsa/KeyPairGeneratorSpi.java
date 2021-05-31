package org.bc.jcajce.provider.asymmetric.rsa;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.generators.RSAKeyPairGenerator;
import org.bc.crypto.params.RSAKeyGenerationParameters;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.crypto.params.RSAPrivateCrtKeyParameters;

public class KeyPairGeneratorSpi extends KeyPairGenerator {
   static final BigInteger defaultPublicExponent = BigInteger.valueOf(65537L);
   static final int defaultTests = 12;
   RSAKeyGenerationParameters param;
   RSAKeyPairGenerator engine;

   public KeyPairGeneratorSpi(String var1) {
      super(var1);
   }

   public KeyPairGeneratorSpi() {
      super("RSA");
      this.engine = new RSAKeyPairGenerator();
      this.param = new RSAKeyGenerationParameters(defaultPublicExponent, new SecureRandom(), 2048, 12);
      this.engine.init(this.param);
   }

   public void initialize(int var1, SecureRandom var2) {
      this.param = new RSAKeyGenerationParameters(defaultPublicExponent, var2, var1, 12);
      this.engine.init(this.param);
   }

   public void initialize(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof RSAKeyGenParameterSpec)) {
         throw new InvalidAlgorithmParameterException("parameter object not a RSAKeyGenParameterSpec");
      } else {
         RSAKeyGenParameterSpec var3 = (RSAKeyGenParameterSpec)var1;
         this.param = new RSAKeyGenerationParameters(var3.getPublicExponent(), var2, var3.getKeysize(), 12);
         this.engine.init(this.param);
      }
   }

   public KeyPair generateKeyPair() {
      AsymmetricCipherKeyPair var1 = this.engine.generateKeyPair();
      RSAKeyParameters var2 = (RSAKeyParameters)var1.getPublic();
      RSAPrivateCrtKeyParameters var3 = (RSAPrivateCrtKeyParameters)var1.getPrivate();
      return new KeyPair(new BCRSAPublicKey(var2), new BCRSAPrivateCrtKey(var3));
   }
}
