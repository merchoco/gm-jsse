package org.bc.crypto;

public interface DerivationFunction {
   void init(DerivationParameters var1);

   Digest getDigest();

   int generateBytes(byte[] var1, int var2, int var3) throws DataLengthException, IllegalArgumentException;
}
