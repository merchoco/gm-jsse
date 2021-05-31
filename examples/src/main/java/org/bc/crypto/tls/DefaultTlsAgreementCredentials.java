package org.bc.crypto.tls;

import java.math.BigInteger;
import org.bc.crypto.BasicAgreement;
import org.bc.crypto.agreement.DHBasicAgreement;
import org.bc.crypto.agreement.ECDHBasicAgreement;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.util.BigIntegers;

public class DefaultTlsAgreementCredentials implements TlsAgreementCredentials {
   protected Certificate clientCert;
   protected AsymmetricKeyParameter clientPrivateKey;
   protected BasicAgreement basicAgreement;

   public DefaultTlsAgreementCredentials(Certificate var1, AsymmetricKeyParameter var2) {
      if (var1 == null) {
         throw new IllegalArgumentException("'clientCertificate' cannot be null");
      } else if (var1.certs.length == 0) {
         throw new IllegalArgumentException("'clientCertificate' cannot be empty");
      } else if (var2 == null) {
         throw new IllegalArgumentException("'clientPrivateKey' cannot be null");
      } else if (!var2.isPrivate()) {
         throw new IllegalArgumentException("'clientPrivateKey' must be private");
      } else {
         if (var2 instanceof DHPrivateKeyParameters) {
            this.basicAgreement = new DHBasicAgreement();
         } else {
            if (!(var2 instanceof ECPrivateKeyParameters)) {
               throw new IllegalArgumentException("'clientPrivateKey' type not supported: " + var2.getClass().getName());
            }

            this.basicAgreement = new ECDHBasicAgreement();
         }

         this.clientCert = var1;
         this.clientPrivateKey = var2;
      }
   }

   public Certificate getCertificate() {
      return this.clientCert;
   }

   public byte[] generateAgreement(AsymmetricKeyParameter var1) {
      this.basicAgreement.init(this.clientPrivateKey);
      BigInteger var2 = this.basicAgreement.calculateAgreement(var1);
      return BigIntegers.asUnsignedByteArray(var2);
   }
}
