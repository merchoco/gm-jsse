package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

class CipherBlockChaining extends FeedbackCipher {
   protected byte[] r;
   private byte[] k;
   private byte[] rSave = null;

   CipherBlockChaining(SymmetricCipher var1) {
      super(var1);
      this.k = new byte[this.blockSize];
      this.r = new byte[this.blockSize];
   }

   String getFeedback() {
      return "CBC";
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
      System.arraycopy(this.iv, 0, this.r, 0, this.blockSize);
   }

   void save() {
      if (this.rSave == null) {
         this.rSave = new byte[this.blockSize];
      }

      System.arraycopy(this.r, 0, this.rSave, 0, this.blockSize);
   }

   void restore() {
      System.arraycopy(this.rSave, 0, this.r, 0, this.blockSize);
   }

   void encrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      for(int var7 = var2 + var3; var2 < var7; var5 += this.blockSize) {
         for(int var6 = 0; var6 < this.blockSize; ++var6) {
            this.k[var6] = (byte)(var1[var6 + var2] ^ this.r[var6]);
         }

         this.embeddedCipher.encryptBlock(this.k, 0, var4, var5);
         System.arraycopy(var4, var5, this.r, 0, this.blockSize);
         var2 += this.blockSize;
      }

   }

   void decrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      byte[] var7 = null;
      int var8 = var2 + var3;
      if (var1 == var4 && var2 >= var5 && var2 - var5 < this.blockSize) {
         var7 = (byte[])var1.clone();
      }

      while(var2 < var8) {
         this.embeddedCipher.decryptBlock(var1, var2, this.k, 0);

         for(int var6 = 0; var6 < this.blockSize; ++var6) {
            var4[var6 + var5] = (byte)(this.k[var6] ^ this.r[var6]);
         }

         if (var7 == null) {
            System.arraycopy(var1, var2, this.r, 0, this.blockSize);
         } else {
            System.arraycopy(var7, var2, this.r, 0, this.blockSize);
         }

         var2 += this.blockSize;
         var5 += this.blockSize;
      }

   }
}
