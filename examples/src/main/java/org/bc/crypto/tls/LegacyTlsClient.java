package org.bc.crypto.tls;

import java.io.IOException;

/** @deprecated */
public class LegacyTlsClient extends DefaultTlsClient {
   /** @deprecated */
   protected CertificateVerifyer verifyer;

   /** @deprecated */
   public LegacyTlsClient(CertificateVerifyer var1) {
      this.verifyer = var1;
   }

   public TlsAuthentication getAuthentication() throws IOException {
      return new LegacyTlsAuthentication(this.verifyer);
   }
}
