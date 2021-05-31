package org.bc.crypto.tls;

import java.io.IOException;
import org.bc.crypto.CryptoException;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DSAPrivateKeyParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.RSAKeyParameters;

public class DefaultTlsSignerCredentials implements TlsSignerCredentials {
   protected TlsClientContext context;
   protected Certificate clientCert;
   protected AsymmetricKeyParameter clientPrivateKey;
   protected TlsSigner clientSigner;

   public DefaultTlsSignerCredentials(TlsClientContext var1, Certificate var2, AsymmetricKeyParameter var3) {
      if (var2 == null) {
         throw new IllegalArgumentException("'clientCertificate' cannot be null");
      } else if (var2.certs.length == 0) {
         throw new IllegalArgumentException("'clientCertificate' cannot be empty");
      } else if (var3 == null) {
         throw new IllegalArgumentException("'clientPrivateKey' cannot be null");
      } else if (!var3.isPrivate()) {
         throw new IllegalArgumentException("'clientPrivateKey' must be private");
      } else {
         if (var3 instanceof RSAKeyParameters) {
            this.clientSigner = new TlsRSASigner();
         } else if (var3 instanceof DSAPrivateKeyParameters) {
            this.clientSigner = new TlsDSSSigner();
         } else {
            if (!(var3 instanceof ECPrivateKeyParameters)) {
               throw new IllegalArgumentException("'clientPrivateKey' type not supported: " + var3.getClass().getName());
            }

            this.clientSigner = new TlsECDSASigner();
         }

         this.context = var1;
         this.clientCert = var2;
         this.clientPrivateKey = var3;
      }
   }

   public Certificate getCertificate() {
      return this.clientCert;
   }

   public byte[] generateCertificateSignature(byte[] var1) throws IOException {
      try {
         return this.clientSigner.calculateRawSignature(this.context.getSecureRandom(), this.clientPrivateKey, var1);
      } catch (CryptoException var3) {
         throw new TlsFatalAlert((short)80);
      }
   }
}
