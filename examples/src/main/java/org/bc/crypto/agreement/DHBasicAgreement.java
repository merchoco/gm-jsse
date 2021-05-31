package org.bc.crypto.agreement;

import java.math.BigInteger;
import org.bc.crypto.BasicAgreement;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.DHPublicKeyParameters;
import org.bc.crypto.params.ParametersWithRandom;

public class DHBasicAgreement implements BasicAgreement {
   private DHPrivateKeyParameters key;
   private DHParameters dhParams;

   public void init(CipherParameters var1) {
      AsymmetricKeyParameter var2;
      if (var1 instanceof ParametersWithRandom) {
         ParametersWithRandom var3 = (ParametersWithRandom)var1;
         var2 = (AsymmetricKeyParameter)var3.getParameters();
      } else {
         var2 = (AsymmetricKeyParameter)var1;
      }

      if (!(var2 instanceof DHPrivateKeyParameters)) {
         throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
      } else {
         this.key = (DHPrivateKeyParameters)var2;
         this.dhParams = this.key.getParameters();
      }
   }

   public int getFieldSize() {
      return (this.key.getParameters().getP().bitLength() + 7) / 8;
   }

   public BigInteger calculateAgreement(CipherParameters var1) {
      DHPublicKeyParameters var2 = (DHPublicKeyParameters)var1;
      if (!var2.getParameters().equals(this.dhParams)) {
         throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
      } else {
         return var2.getY().modPow(this.key.getX(), this.dhParams.getP());
      }
   }
}
