package org.bc.crypto.generators;

import java.math.BigInteger;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.ElGamalKeyGenerationParameters;
import org.bc.crypto.params.ElGamalParameters;
import org.bc.crypto.params.ElGamalPrivateKeyParameters;
import org.bc.crypto.params.ElGamalPublicKeyParameters;

public class ElGamalKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
   private ElGamalKeyGenerationParameters param;

   public void init(KeyGenerationParameters var1) {
      this.param = (ElGamalKeyGenerationParameters)var1;
   }

   public AsymmetricCipherKeyPair generateKeyPair() {
      DHKeyGeneratorHelper var1 = DHKeyGeneratorHelper.INSTANCE;
      ElGamalParameters var2 = this.param.getParameters();
      DHParameters var3 = new DHParameters(var2.getP(), var2.getG(), (BigInteger)null, var2.getL());
      BigInteger var4 = var1.calculatePrivate(var3, this.param.getRandom());
      BigInteger var5 = var1.calculatePublic(var3, var4);
      return new AsymmetricCipherKeyPair(new ElGamalPublicKeyParameters(var5, var2), new ElGamalPrivateKeyParameters(var4, var2));
   }
}
