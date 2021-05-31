package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

final class OutputFeedback extends FeedbackCipher {
   private byte[] k = null;
   private byte[] register = null;
   private int numBytes;
   private byte[] registerSave = null;

   OutputFeedback(SymmetricCipher var1, int var2) {
      super(var1);
      if (var2 > this.blockSize) {
         var2 = this.blockSize;
      }

      this.numBytes = var2;
      this.k = new byte[this.blockSize];
      this.register = new byte[this.blockSize];
   }

   String getFeedback() {
      return "OFB";
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

   void reset() {
      System.arraycopy(this.iv, 0, this.register, 0, this.blockSize);
   }

   void save() {
      if (this.registerSave == null) {
         this.registerSave = new byte[this.blockSize];
      }

      System.arraycopy(this.register, 0, this.registerSave, 0, this.blockSize);
   }

   void restore() {
      System.arraycopy(this.registerSave, 0, this.register, 0, this.blockSize);
   }

   void encrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      int var7 = this.blockSize - this.numBytes;
      int var8 = var3 / this.numBytes;
      int var9 = var3 % this.numBytes;
      int var6;
      if (var7 == 0) {
         while(true) {
            if (var8 <= 0) {
               if (var9 > 0) {
                  this.embeddedCipher.encryptBlock(this.register, 0, this.k, 0);

                  for(var6 = 0; var6 < var9; ++var6) {
                     var4[var6 + var5] = (byte)(this.k[var6] ^ var1[var6 + var2]);
                  }

                  System.arraycopy(this.k, 0, this.register, 0, this.numBytes);
               }
               break;
            }

            this.embeddedCipher.encryptBlock(this.register, 0, this.k, 0);

            for(var6 = 0; var6 < this.numBytes; ++var6) {
               var4[var6 + var5] = (byte)(this.k[var6] ^ var1[var6 + var2]);
            }

            System.arraycopy(this.k, 0, this.register, 0, this.numBytes);
            var2 += this.numBytes;
            var5 += this.numBytes;
            --var8;
         }
      } else {
         while(true) {
            if (var8 <= 0) {
               if (var9 > 0) {
                  this.embeddedCipher.encryptBlock(this.register, 0, this.k, 0);

                  for(var6 = 0; var6 < var9; ++var6) {
                     var4[var6 + var5] = (byte)(this.k[var6] ^ var1[var6 + var2]);
                  }

                  System.arraycopy(this.register, this.numBytes, this.register, 0, var7);
                  System.arraycopy(this.k, 0, this.register, var7, this.numBytes);
               }
               break;
            }

            this.embeddedCipher.encryptBlock(this.register, 0, this.k, 0);

            for(var6 = 0; var6 < this.numBytes; ++var6) {
               var4[var6 + var5] = (byte)(this.k[var6] ^ var1[var6 + var2]);
            }

            System.arraycopy(this.register, this.numBytes, this.register, 0, var7);
            System.arraycopy(this.k, 0, this.register, var7, this.numBytes);
            var2 += this.numBytes;
            var5 += this.numBytes;
            --var8;
         }
      }

   }

   void decrypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      this.encrypt(var1, var2, var3, var4, var5);
   }
}
