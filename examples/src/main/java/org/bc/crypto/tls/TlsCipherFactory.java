package org.bc.crypto.tls;

import java.io.IOException;

public interface TlsCipherFactory {
   TlsCipher createCipher(TlsClientContext var1, int var2, int var3) throws IOException;
}
