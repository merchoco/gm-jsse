package org.bc.pqc.crypto;

import org.bc.crypto.CipherParameters;

public interface MessageSigner {
   void init(boolean var1, CipherParameters var2);

   byte[] generateSignature(byte[] var1);

   boolean verifySignature(byte[] var1, byte[] var2);
}
