package org.bc.crypto;

public interface StreamCipher {
   void init(boolean var1, CipherParameters var2) throws IllegalArgumentException;

   String getAlgorithmName();

   byte returnByte(byte var1);

   void processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) throws DataLengthException;

   void reset();
}
