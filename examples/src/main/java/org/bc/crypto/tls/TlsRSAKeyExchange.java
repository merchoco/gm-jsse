package org.bc.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.crypto.util.PublicKeyFactory;

class TlsRSAKeyExchange implements TlsKeyExchange {
   protected TlsClientContext context;
   protected AsymmetricKeyParameter serverPublicKey = null;
   protected RSAKeyParameters rsaServerPublicKey = null;
   protected byte[] premasterSecret;

   TlsRSAKeyExchange(TlsClientContext var1) {
      this.context = var1;
   }

   public void skipServerCertificate() throws IOException {
      throw new TlsFatalAlert((short)10);
   }

   public void processServerCertificate(Certificate var1) throws IOException {
      org.bc.asn1.x509.Certificate var2 = var1.certs[0];
      SubjectPublicKeyInfo var3 = var2.getSubjectPublicKeyInfo();

      try {
         this.serverPublicKey = PublicKeyFactory.createKey(var3);
      } catch (RuntimeException var5) {
         throw new TlsFatalAlert((short)43);
      }

      if (this.serverPublicKey.isPrivate()) {
         throw new TlsFatalAlert((short)80);
      } else {
         this.rsaServerPublicKey = this.validateRSAPublicKey((RSAKeyParameters)this.serverPublicKey);
         TlsUtils.validateKeyUsage(var2, 32);
      }
   }

   public void skipServerKeyExchange() throws IOException {
   }

   public void processServerKeyExchange(InputStream var1) throws IOException {
      throw new TlsFatalAlert((short)10);
   }

   public void validateCertificateRequest(CertificateRequest var1) throws IOException {
      short[] var2 = var1.getCertificateTypes();
      int var3 = 0;

      while(var3 < var2.length) {
         switch(var2[var3]) {
         case 1:
         case 2:
         case 64:
            ++var3;
            break;
         default:
            throw new TlsFatalAlert((short)47);
         }
      }

   }

   public void skipClientCredentials() throws IOException {
   }

   public void processClientCredentials(TlsCredentials var1) throws IOException {
      if (!(var1 instanceof TlsSignerCredentials)) {
         throw new TlsFatalAlert((short)80);
      }
   }

   public void generateClientKeyExchange(OutputStream var1) throws IOException {
      this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(this.context, this.rsaServerPublicKey, var1);
   }

   public byte[] generatePremasterSecret() throws IOException {
      byte[] var1 = this.premasterSecret;
      this.premasterSecret = null;
      return var1;
   }

   protected RSAKeyParameters validateRSAPublicKey(RSAKeyParameters var1) throws IOException {
      if (!var1.getExponent().isProbablePrime(2)) {
         throw new TlsFatalAlert((short)47);
      } else {
         return var1;
      }
   }
}
