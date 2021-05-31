package org.bc.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.params.GOST3410KeyGenerationParameters;
import org.bc.crypto.params.GOST3410Parameters;
import org.bc.crypto.params.GOST3410PrivateKeyParameters;
import org.bc.crypto.params.GOST3410PublicKeyParameters;

public class GOST3410KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
   private static final BigInteger ZERO = BigInteger.valueOf(0L);
   private GOST3410KeyGenerationParameters param;

   public void init(KeyGenerationParameters var1) {
      this.param = (GOST3410KeyGenerationParameters)var1;
   }

   public AsymmetricCipherKeyPair generateKeyPair() {
      GOST3410Parameters var6 = this.param.getParameters();
      SecureRandom var7 = this.param.getRandom();
      BigInteger var2 = var6.getQ();
      BigInteger var1 = var6.getP();
      BigInteger var3 = var6.getA();

      BigInteger var4;
      do {
         do {
            var4 = new BigInteger(256, var7);
         } while(var4.equals(ZERO));
      } while(var4.compareTo(var2) >= 0);

      BigInteger var5 = var3.modPow(var4, var1);
      return new AsymmetricCipherKeyPair(new GOST3410PublicKeyParameters(var5, var6), new GOST3410PrivateKeyParameters(var4, var6));
   }
}
