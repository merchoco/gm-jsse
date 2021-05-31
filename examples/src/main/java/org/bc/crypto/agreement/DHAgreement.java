package org.bc.crypto.agreement;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.generators.DHKeyPairGenerator;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DHKeyGenerationParameters;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.DHPublicKeyParameters;
import org.bc.crypto.params.ParametersWithRandom;

public class DHAgreement {
   private DHPrivateKeyParameters key;
   private DHParameters dhParams;
   private BigInteger privateValue;
   private SecureRandom random;

   public void init(CipherParameters var1) {
      AsymmetricKeyParameter var2;
      if (var1 instanceof ParametersWithRandom) {
         ParametersWithRandom var3 = (ParametersWithRandom)var1;
         this.random = var3.getRandom();
         var2 = (AsymmetricKeyParameter)var3.getParameters();
      } else {
         this.random = new SecureRandom();
         var2 = (AsymmetricKeyParameter)var1;
      }

      if (!(var2 instanceof DHPrivateKeyParameters)) {
         throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
      } else {
         this.key = (DHPrivateKeyParameters)var2;
         this.dhParams = this.key.getParameters();
      }
   }

   public BigInteger calculateMessage() {
      DHKeyPairGenerator var1 = new DHKeyPairGenerator();
      var1.init(new DHKeyGenerationParameters(this.random, this.dhParams));
      AsymmetricCipherKeyPair var2 = var1.generateKeyPair();
      this.privateValue = ((DHPrivateKeyParameters)var2.getPrivate()).getX();
      return ((DHPublicKeyParameters)var2.getPublic()).getY();
   }

   public BigInteger calculateAgreement(DHPublicKeyParameters var1, BigInteger var2) {
      if (!var1.getParameters().equals(this.dhParams)) {
         throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
      } else {
         BigInteger var3 = this.dhParams.getP();
         return var2.modPow(this.key.getX(), var3).multiply(var1.getY().modPow(this.privateValue, var3)).mod(var3);
      }
   }
}
