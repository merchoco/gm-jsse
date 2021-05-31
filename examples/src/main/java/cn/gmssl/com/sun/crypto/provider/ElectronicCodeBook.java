package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

final class ElectronicCodeBook extends FeedbackCipher {
   ElectronicCodeBook(SymmetricCipher var1) {
      super(var1);
   }

   String getFeedback() {
      return "ECB";
   }

   void reset() {
   }

   void save() {
   }

   void restore() {
   }

   void init(boolean var1, String var2, byte[] var3, byte[] var4) throws InvalidKeyException {
      if (var3 != null && var4 == null) {
         this.embeddedCipher.init(var1, var2, var3);
      } else {
         throw new InvalidKeyException("Internal error");
      }
   }

   void encrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      while(var3 >= this.blockSize) {
         this.embeddedCipher.encryptBlock(var1, var2, var4, var5);
         var3 -= this.blockSize;
         var2 += this.blockSize;
         var5 += this.blockSize;
      }

   }

   void decrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      while(var3 >= this.blockSize) {
         this.embeddedCipher.decryptBlock(var1, var2, var4, var5);
         var3 -= this.blockSize;
         var2 += this.blockSize;
         var5 += this.blockSize;
      }

   }
}
