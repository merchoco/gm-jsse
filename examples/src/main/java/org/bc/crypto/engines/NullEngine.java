package org.bc.crypto.engines;

import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;

public class NullEngine implements BlockCipher {
   private boolean initialised;
   protected static final int BLOCK_SIZE = 1;

   public void init(boolean var1, CipherParameters var2) throws IllegalArgumentException {
      this.initialised = true;
   }

   public String getAlgorithmName() {
      return "Null";
   }

   public int getBlockSize() {
      return 1;
   }

   public int processBlock(byte[] var1, int var2, byte[] var3, int var4) throws DataLengthException, IllegalStateException {
      if (!this.initialised) {
         throw new IllegalStateException("Null engine not initialised");
      } else if (var2 + 1 > var1.length) {
         throw new DataLengthException("input buffer too short");
      } else if (var4 + 1 > var3.length) {
         throw new DataLengthException("output buffer too short");
      } else {
         for(int var5 = 0; var5 < 1; ++var5) {
            var3[var4 + var5] = var1[var2 + var5];
         }

         return 1;
      }
   }

   public void reset() {
   }
}
