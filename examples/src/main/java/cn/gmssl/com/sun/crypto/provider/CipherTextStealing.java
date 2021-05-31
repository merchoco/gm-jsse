package cn.gmssl.com.sun.crypto.provider;

import javax.crypto.IllegalBlockSizeException;

final class CipherTextStealing extends CipherBlockChaining {
   CipherTextStealing(SymmetricCipher var1) {
      super(var1);
   }

   String getFeedback() {
      return "CTS";
   }

   void encryptFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws IllegalBlockSizeException {
      if (var3 < this.blockSize) {
         throw new IllegalBlockSizeException("input is too short!");
      } else {
         if (var3 == this.blockSize) {
            this.encrypt(var1, var2, var3, var4, var5);
         } else {
            int var6 = var3 % this.blockSize;
            int var7;
            byte[] var9;
            if (var6 == 0) {
               this.encrypt(var1, var2, var3, var4, var5);
               var7 = var5 + var3 - this.blockSize;
               int var8 = var7 - this.blockSize;
               var9 = new byte[this.blockSize];
               System.arraycopy(var4, var7, var9, 0, this.blockSize);
               System.arraycopy(var4, var8, var4, var7, this.blockSize);
               System.arraycopy(var9, 0, var4, var8, this.blockSize);
            } else {
               var7 = var3 - (this.blockSize + var6);
               if (var7 > 0) {
                  this.encrypt(var1, var2, var7, var4, var5);
                  var2 += var7;
                  var5 += var7;
               }

               byte[] var11 = new byte[this.blockSize];

               for(int var12 = 0; var12 < this.blockSize; ++var12) {
                  var11[var12] = (byte)(var1[var2 + var12] ^ this.r[var12]);
               }

               var9 = new byte[this.blockSize];
               this.embeddedCipher.encryptBlock(var11, 0, var9, 0);
               System.arraycopy(var9, 0, var4, var5 + this.blockSize, var6);

               for(int var10 = 0; var10 < var6; ++var10) {
                  var9[var10] ^= var1[var2 + this.blockSize + var10];
               }

               this.embeddedCipher.encryptBlock(var9, 0, var4, var5);
            }
         }

      }
   }

   void decryptFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws IllegalBlockSizeException {
      if (var3 < this.blockSize) {
         throw new IllegalBlockSizeException("input is too short!");
      } else {
         if (var3 == this.blockSize) {
            this.decrypt(var1, var2, var3, var4, var5);
         } else {
            int var6 = var3 % this.blockSize;
            int var7;
            if (var6 == 0) {
               var7 = var2 + var3 - this.blockSize;
               int var8 = var2 + var3 - 2 * this.blockSize;
               byte[] var9 = new byte[2 * this.blockSize];
               System.arraycopy(var1, var7, var9, 0, this.blockSize);
               System.arraycopy(var1, var8, var9, this.blockSize, this.blockSize);
               int var10 = var3 - 2 * this.blockSize;
               this.decrypt(var1, var2, var10, var4, var5);
               this.decrypt(var9, 0, 2 * this.blockSize, var4, var5 + var10);
            } else {
               var7 = var3 - (this.blockSize + var6);
               if (var7 > 0) {
                  this.decrypt(var1, var2, var7, var4, var5);
                  var2 += var7;
                  var5 += var7;
               }

               byte[] var11 = new byte[this.blockSize];
               this.embeddedCipher.decryptBlock(var1, var2, var11, 0);

               int var12;
               for(var12 = 0; var12 < var6; ++var12) {
                  var4[var5 + this.blockSize + var12] = (byte)(var1[var2 + this.blockSize + var12] ^ var11[var12]);
               }

               System.arraycopy(var1, var2 + this.blockSize, var11, 0, var6);
               this.embeddedCipher.decryptBlock(var11, 0, var4, var5);

               for(var12 = 0; var12 < this.blockSize; ++var12) {
                  var4[var5 + var12] ^= this.r[var12];
               }
            }
         }

      }
   }
}
