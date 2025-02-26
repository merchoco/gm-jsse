package org.bc.crypto.modes;

import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.InvalidCipherTextException;

public interface AEADBlockCipher {
   void init(boolean var1, CipherParameters var2) throws IllegalArgumentException;

   String getAlgorithmName();

   BlockCipher getUnderlyingCipher();

   void processAADByte(byte var1);

   void processAADBytes(byte[] var1, int var2, int var3);

   int processByte(byte var1, byte[] var2, int var3) throws DataLengthException;

   int processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) throws DataLengthException;

   int doFinal(byte[] var1, int var2) throws IllegalStateException, InvalidCipherTextException;

   byte[] getMac();

   int getUpdateOutputSize(int var1);

   int getOutputSize(int var1);

   void reset();
}
