package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;

abstract class FeedbackCipher {
   final SymmetricCipher embeddedCipher;
   final int blockSize;
   byte[] iv;

   FeedbackCipher(SymmetricCipher var1) {
      this.embeddedCipher = var1;
      this.blockSize = var1.getBlockSize();
   }

   final SymmetricCipher getEmbeddedCipher() {
      return this.embeddedCipher;
   }

   final int getBlockSize() {
      return this.blockSize;
   }

   abstract String getFeedback();

   abstract void save();

   abstract void restore();

   abstract void init(boolean var1, String var2, byte[] var3, byte[] var4) throws InvalidKeyException;

   final byte[] getIV() {
      return this.iv;
   }

   abstract void reset();

   abstract void encrypt(byte[] var1, int var2, int var3, byte[] var4, int var5);

   void encryptFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws IllegalBlockSizeException {
      this.encrypt(var1, var2, var3, var4, var5);
   }

   abstract void decrypt(byte[] var1, int var2, int var3, byte[] var4, int var5);

   void decryptFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws IllegalBlockSizeException {
      this.decrypt(var1, var2, var3, var4, var5);
   }
}
