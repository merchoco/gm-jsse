package org.bc.pqc.crypto;

import org.bc.crypto.CipherParameters;

public interface MessageEncryptor {
   void init(boolean var1, CipherParameters var2);

   byte[] messageEncrypt(byte[] var1) throws Exception;

   byte[] messageDecrypt(byte[] var1) throws Exception;
}
