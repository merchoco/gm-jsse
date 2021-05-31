package org.bc.crypto.tls;

import java.io.IOException;
import org.bc.crypto.params.AsymmetricKeyParameter;

public interface TlsAgreementCredentials extends TlsCredentials {
   byte[] generateAgreement(AsymmetricKeyParameter var1) throws IOException;
}
