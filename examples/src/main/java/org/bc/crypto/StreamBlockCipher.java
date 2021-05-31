package org.bc.crypto;

public class StreamBlockCipher implements StreamCipher {
   private BlockCipher cipher;
   private byte[] oneByte = new byte[1];

   public StreamBlockCipher(BlockCipher var1) {
      if (var1.getBlockSize() != 1) {
         throw new IllegalArgumentException("block cipher block size != 1.");
      } else {
         this.cipher = var1;
      }
   }

   public void init(boolean var1, CipherParameters var2) {
      this.cipher.init(var1, var2);
   }

   public String getAlgorithmName() {
      return this.cipher.getAlgorithmName();
   }

   public byte returnByte(byte var1) {
      this.oneByte[0] = var1;
      this.cipher.processBlock(this.oneByte, 0, this.oneByte, 0);
      return this.oneByte[0];
   }

   public void processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) throws DataLengthException {
      if (var5 + var3 > var4.length) {
         throw new DataLengthException("output buffer too small in processBytes()");
      } else {
         for(int var6 = 0; var6 != var3; ++var6) {
            this.cipher.processBlock(var1, var2 + var6, var4, var5 + var6);
         }

      }
   }

   public void reset() {
      this.cipher.reset();
   }
}
