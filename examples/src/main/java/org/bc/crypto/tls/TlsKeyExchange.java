package org.bc.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface TlsKeyExchange {
   void skipServerCertificate() throws IOException;

   void processServerCertificate(Certificate var1) throws IOException;

   void skipServerKeyExchange() throws IOException;

   void processServerKeyExchange(InputStream var1) throws IOException;

   void validateCertificateRequest(CertificateRequest var1) throws IOException;

   void skipClientCredentials() throws IOException;

   void processClientCredentials(TlsCredentials var1) throws IOException;

   void generateClientKeyExchange(OutputStream var1) throws IOException;

   byte[] generatePremasterSecret() throws IOException;
}
