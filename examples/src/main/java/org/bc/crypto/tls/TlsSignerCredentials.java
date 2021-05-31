package org.bc.crypto.tls;

import java.io.IOException;

public interface TlsSignerCredentials extends TlsCredentials {
   byte[] generateCertificateSignature(byte[] var1) throws IOException;
}
