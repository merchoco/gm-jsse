package org.bc.crypto.generators;

import java.math.BigInteger;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.params.DHKeyGenerationParameters;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.DHPublicKeyParameters;

public class DHKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
   private DHKeyGenerationParameters param;

   public void init(KeyGenerationParameters var1) {
      this.param = (DHKeyGenerationParameters)var1;
   }

   public AsymmetricCipherKeyPair generateKeyPair() {
      DHKeyGeneratorHelper var1 = DHKeyGeneratorHelper.INSTANCE;
      DHParameters var2 = this.param.getParameters();
      BigInteger var3 = var1.calculatePrivate(var2, this.param.getRandom());
      BigInteger var4 = var1.calculatePublic(var2, var3);
      return new AsymmetricCipherKeyPair(new DHPublicKeyParameters(var4, var2), new DHPrivateKeyParameters(var3, var2));
   }
}
