package org.bc.crypto.modes;

import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.params.ParametersWithIV;

public class SICBlockCipher implements BlockCipher {
   private final BlockCipher cipher;
   private final int blockSize;
   private byte[] IV;
   private byte[] counter;
   private byte[] counterOut;

   public SICBlockCipher(BlockCipher var1) {
      this.cipher = var1;
      this.blockSize = this.cipher.getBlockSize();
      this.IV = new byte[this.blockSize];
      this.counter = new byte[this.blockSize];
      this.counterOut = new byte[this.blockSize];
   }

   public BlockCipher getUnderlyingCipher() {
      return this.cipher;
   }

   public void init(boolean var1, CipherParameters var2) throws IllegalArgumentException {
      if (var2 instanceof ParametersWithIV) {
         ParametersWithIV var3 = (ParametersWithIV)var2;
         byte[] var4 = var3.getIV();
         System.arraycopy(var4, 0, this.IV, 0, this.IV.length);
         this.reset();
         if (var3.getParameters() != null) {
            this.cipher.init(true, var3.getParameters());
         }

      } else {
         throw new IllegalArgumentException("SIC mode requires ParametersWithIV");
      }
   }

   public String getAlgorithmName() {
      return this.cipher.getAlgorithmName() + "/SIC";
   }

   public int getBlockSize() {
      return this.cipher.getBlockSize();
   }

   public int processBlock(byte[] var1, int var2, byte[] var3, int var4) throws DataLengthException, IllegalStateException {
      this.cipher.processBlock(this.counter, 0, this.counterOut, 0);

      int var5;
      for(var5 = 0; var5 < this.counterOut.length; ++var5) {
         var3[var4 + var5] = (byte)(this.counterOut[var5] ^ var1[var2 + var5]);
      }

      for(var5 = this.counter.length - 1; var5 >= 0 && ++this.counter[var5] == 0; --var5) {
         ;
      }

      return this.counter.length;
   }

   public void reset() {
      System.arraycopy(this.IV, 0, this.counter, 0, this.counter.length);
      this.cipher.reset();
   }
}
