package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

final class PCBC extends FeedbackCipher {
   private final byte[] k;
   private byte[] kSave = null;

   PCBC(SymmetricCipher var1) {
      super(var1);
      this.k = new byte[this.blockSize];
   }

   String getFeedback() {
      return "PCBC";
   }

   void init(boolean var1, String var2, byte[] var3, byte[] var4) throws InvalidKeyException {
      if (var3 != null && var4 != null && var4.length == this.blockSize) {
         this.iv = var4;
         this.reset();
         this.embeddedCipher.init(var1, var2, var3);
      } else {
         throw new InvalidKeyException("Internal error");
      }
   }

   void reset() {
      System.arraycopy(this.iv, 0, this.k, 0, this.blockSize);
   }

   void save() {
      if (this.kSave == null) {
         this.kSave = new byte[this.blockSize];
      }

      System.arraycopy(this.k, 0, this.kSave, 0, this.blockSize);
   }

   void restore() {
      System.arraycopy(this.kSave, 0, this.k, 0, this.blockSize);
   }

   void encrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      for(int var7 = var2 + var3; var2 < var7; var5 += this.blockSize) {
         int var6;
         for(var6 = 0; var6 < this.blockSize; ++var6) {
            this.k[var6] ^= var1[var6 + var2];
         }

         this.embeddedCipher.encryptBlock(this.k, 0, var4, var5);

         for(var6 = 0; var6 < this.blockSize; ++var6) {
            this.k[var6] = (byte)(var1[var6 + var2] ^ var4[var6 + var5]);
         }

         var2 += this.blockSize;
      }

   }

   void decrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      for(int var7 = var2 + var3; var2 < var7; var2 += this.blockSize) {
         this.embeddedCipher.decryptBlock(var1, var2, var4, var5);

         int var6;
         for(var6 = 0; var6 < this.blockSize; ++var6) {
            var4[var6 + var5] ^= this.k[var6];
         }

         for(var6 = 0; var6 < this.blockSize; ++var6) {
            this.k[var6] = (byte)(var4[var6 + var5] ^ var1[var6 + var2]);
         }

         var5 += this.blockSize;
      }

   }
}
