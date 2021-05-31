package org.bc.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.engines.MyBigInteger;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECKeyGenerationParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.math.ec.ECConstants;
import org.bc.math.ec.ECPoint;

public class ECKeyPairGenerator implements AsymmetricCipherKeyPairGenerator, ECConstants {
   ECDomainParameters params;
   SecureRandom random;

   public void init(KeyGenerationParameters var1) {
      ECKeyGenerationParameters var2 = (ECKeyGenerationParameters)var1;
      this.random = var2.getRandom();
      this.params = var2.getDomainParameters();
   }

   public AsymmetricCipherKeyPair generateKeyPair() {
      BigInteger var1 = this.params.getN();
      int var2 = var1.bitLength();
      BigInteger var3 = MyBigInteger.gen(var1, this.random);
      ECPoint var4 = this.params.getG().multiply(var3);
      return new AsymmetricCipherKeyPair(new ECPublicKeyParameters(var4, this.params), new ECPrivateKeyParameters(var3, this.params));
   }
}
