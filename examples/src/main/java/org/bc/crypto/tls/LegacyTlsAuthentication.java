package org.bc.crypto.tls;

import java.io.IOException;

/** @deprecated */
public class LegacyTlsAuthentication implements TlsAuthentication {
   protected CertificateVerifyer verifyer;

   public LegacyTlsAuthentication(CertificateVerifyer var1) {
      this.verifyer = var1;
   }

   public void notifyServerCertificate(Certificate var1) throws IOException {
      if (!this.verifyer.isValid(var1.getCerts())) {
         throw new TlsFatalAlert((short)90);
      }
   }

   public TlsCredentials getClientCredentials(CertificateRequest var1) throws IOException {
      return null;
   }
}
