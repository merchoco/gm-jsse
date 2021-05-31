package org.bc.crypto.agreement;

import java.math.BigInteger;
import org.bc.crypto.BasicAgreement;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.math.ec.ECPoint;

public class ECDHCBasicAgreement implements BasicAgreement {
   ECPrivateKeyParameters key;

   public void init(CipherParameters var1) {
      this.key = (ECPrivateKeyParameters)var1;
   }

   public int getFieldSize() {
      return (this.key.getParameters().getCurve().getFieldSize() + 7) / 8;
   }

   public BigInteger calculateAgreement(CipherParameters var1) {
      ECPublicKeyParameters var2 = (ECPublicKeyParameters)var1;
      ECDomainParameters var3 = var2.getParameters();
      ECPoint var4 = var2.getQ().multiply(var3.getH().multiply(this.key.getD()));
      return var4.getX().toBigInteger();
   }
}
