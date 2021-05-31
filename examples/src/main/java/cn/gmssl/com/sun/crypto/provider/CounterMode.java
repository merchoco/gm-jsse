package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

final class CounterMode extends FeedbackCipher {
   private final byte[] counter;
   private final byte[] encryptedCounter;
   private int used;
   private byte[] counterSave = null;
   private byte[] encryptedCounterSave = null;
   private int usedSave = 0;

   CounterMode(SymmetricCipher var1) {
      super(var1);
      this.counter = new byte[this.blockSize];
      this.encryptedCounter = new byte[this.blockSize];
   }

   String getFeedback() {
      return "CTR";
   }

   void reset() {
      System.arraycopy(this.iv, 0, this.counter, 0, this.blockSize);
      this.used = this.blockSize;
   }

   void save() {
      if (this.counterSave == null) {
         this.counterSave = new byte[this.blockSize];
         this.encryptedCounterSave = new byte[this.blockSize];
      }

      System.arraycopy(this.counter, 0, this.counterSave, 0, this.blockSize);
      System.arraycopy(this.encryptedCounter, 0, this.encryptedCounterSave, 0, this.blockSize);
      this.usedSave = this.used;
   }

   void restore() {
      System.arraycopy(this.counterSave, 0, this.counter, 0, this.blockSize);
      System.arraycopy(this.encryptedCounterSave, 0, this.encryptedCounter, 0, this.blockSize);
      this.used = this.usedSave;
   }

   void init(boolean var1, String var2, byte[] var3, byte[] var4) throws InvalidKeyException {
      if (var3 != null && var4 != null && var4.length == this.blockSize) {
         this.iv = var4;
         this.reset();
         this.embeddedCipher.init(false, var2, var3);
      } else {
         throw new InvalidKeyException("Internal error");
      }
   }

   void encrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      this.crypt(var1, var2, var3, var4, var5);
   }

   void decrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      this.crypt(var1, var2, var3, var4, var5);
   }

   private static void increment(byte[] var0) {
      for(int var1 = var0.length - 1; var1 >= 0 && ++var0[var1] == 0; --var1) {
         ;
      }

   }

   private void crypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      for(; var3-- > 0; var4[var5++] = (byte)(var1[var2++] ^ this.encryptedCounter[this.used++])) {
         if (this.used >= this.blockSize) {
            this.embeddedCipher.encryptBlock(this.counter, 0, this.encryptedCounter, 0);
            increment(this.counter);
            this.used = 0;
         }
      }

   }
}
