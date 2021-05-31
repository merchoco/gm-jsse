package org.bc.crypto.tls;

import java.io.IOException;

public interface TlsCipher {
   byte[] encodePlaintext(short var1, byte[] var2, int var3, int var4) throws IOException;

   byte[] decodeCiphertext(short var1, byte[] var2, int var3, int var4) throws IOException;
}
