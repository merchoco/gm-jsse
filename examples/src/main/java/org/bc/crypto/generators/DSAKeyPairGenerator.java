package org.bc.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.params.DSAKeyGenerationParameters;
import org.bc.crypto.params.DSAParameters;
import org.bc.crypto.params.DSAPrivateKeyParameters;
import org.bc.crypto.params.DSAPublicKeyParameters;
import org.bc.util.BigIntegers;

public class DSAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
   private static final BigInteger ONE = BigInteger.valueOf(1L);
   private DSAKeyGenerationParameters param;

   public void init(KeyGenerationParameters var1) {
      this.param = (DSAKeyGenerationParameters)var1;
   }

   public AsymmetricCipherKeyPair generateKeyPair() {
      DSAParameters var1 = this.param.getParameters();
      BigInteger var2 = generatePrivateKey(var1.getQ(), this.param.getRandom());
      BigInteger var3 = calculatePublicKey(var1.getP(), var1.getG(), var2);
      return new AsymmetricCipherKeyPair(new DSAPublicKeyParameters(var3, var1), new DSAPrivateKeyParameters(var2, var1));
   }

   private static BigInteger generatePrivateKey(BigInteger var0, SecureRandom var1) {
      return BigIntegers.createRandomInRange(ONE, var0.subtract(ONE), var1);
   }

   private static BigInteger calculatePublicKey(BigInteger var0, BigInteger var1, BigInteger var2) {
      return var1.modPow(var2, var0);
   }
}
