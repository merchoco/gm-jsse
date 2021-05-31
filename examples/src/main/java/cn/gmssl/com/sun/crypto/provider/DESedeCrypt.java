package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

final class DESedeCrypt extends DESCrypt implements DESConstants {
   private byte[] key1 = null;
   private byte[] key2 = null;
   private byte[] key3 = null;
   private byte[] buf1 = new byte[8];
   private byte[] buf2 = new byte[8];

   void init(boolean var1, String var2, byte[] var3) throws InvalidKeyException {
      if (!var2.equalsIgnoreCase("DESede") && !var2.equalsIgnoreCase("TripleDES")) {
         throw new InvalidKeyException("Wrong algorithm: DESede or TripleDES required");
      } else if (var3.length != 24) {
         throw new InvalidKeyException("Wrong key size");
      } else {
         byte[] var4 = new byte[8];
         this.key1 = new byte[128];
         System.arraycopy(var3, 0, var4, 0, 8);
         this.expandKey(var4);
         System.arraycopy(this.expandedKey, 0, this.key1, 0, 128);
         if (this.keyEquals(var4, 0, var3, 16, 8)) {
            this.key3 = this.key1;
         } else {
            this.key3 = new byte[128];
            System.arraycopy(var3, 16, var4, 0, 8);
            this.expandKey(var4);
            System.arraycopy(this.expandedKey, 0, this.key3, 0, 128);
         }

         this.key2 = new byte[128];
         System.arraycopy(var3, 8, var4, 0, 8);
         this.expandKey(var4);
         System.arraycopy(this.expandedKey, 0, this.key2, 0, 128);
      }
   }

   void encryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      this.expandedKey = this.key1;
      this.decrypting = false;
      this.cipherBlock(var1, var2, this.buf1, 0);
      this.expandedKey = this.key2;
      this.decrypting = true;
      this.cipherBlock(this.buf1, 0, this.buf2, 0);
      this.expandedKey = this.key3;
      this.decrypting = false;
      this.cipherBlock(this.buf2, 0, var3, var4);
   }

   void decryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      this.expandedKey = this.key3;
      this.decrypting = true;
      this.cipherBlock(var1, var2, this.buf1, 0);
      this.expandedKey = this.key2;
      this.decrypting = false;
      this.cipherBlock(this.buf1, 0, this.buf2, 0);
      this.expandedKey = this.key1;
      this.decrypting = true;
      this.cipherBlock(this.buf2, 0, var3, var4);
   }

   private boolean keyEquals(byte[] var1, int var2, byte[] var3, int var4, int var5) {
      for(int var6 = 0; var6 < var5; ++var6) {
         if (var1[var6 + var2] != var3[var6 + var4]) {
            return false;
         }
      }

      return true;
   }
}
