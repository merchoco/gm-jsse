package org.bc.crypto.paddings;

import java.security.SecureRandom;
import org.bc.crypto.InvalidCipherTextException;

public interface BlockCipherPadding {
   void init(SecureRandom var1) throws IllegalArgumentException;

   String getPaddingName();

   int addPadding(byte[] var1, int var2);

   int padCount(byte[] var1) throws InvalidCipherTextException;
}
