package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

final class RC2Crypt extends SymmetricCipher {
   private static final int[] PI_TABLE = new int[]{217, 120, 249, 196, 25, 221, 181, 237, 40, 233, 253, 121, 74, 160, 216, 157, 198, 126, 55, 131, 43, 118, 83, 142, 98, 76, 100, 136, 68, 139, 251, 162, 23, 154, 89, 245, 135, 179, 79, 19, 97, 69, 109, 141, 9, 129, 125, 50, 189, 143, 64, 235, 134, 183, 123, 11, 240, 149, 33, 34, 92, 107, 78, 130, 84, 214, 101, 147, 206, 96, 178, 28, 115, 86, 192, 20, 167, 140, 241, 220, 18, 117, 202, 31, 59, 190, 228, 209, 66, 61, 212, 48, 163, 60, 182, 38, 111, 191, 14, 218, 70, 105, 7, 87, 39, 242, 29, 155, 188, 148, 67, 3, 248, 17, 199, 246, 144, 239, 62, 231, 6, 195, 213, 47, 200, 102, 30, 215, 8, 232, 234, 222, 128, 82, 238, 247, 132, 170, 114, 172, 53, 77, 106, 42, 150, 26, 210, 113, 90, 21, 73, 116, 75, 159, 208, 94, 4, 24, 164, 236, 194, 224, 65, 110, 15, 81, 203, 204, 36, 145, 175, 80, 161, 244, 112, 57, 153, 124, 58, 133, 35, 184, 180, 122, 252, 2, 54, 91, 37, 85, 151, 49, 45, 93, 250, 152, 227, 138, 146, 174, 5, 223, 41, 16, 103, 108, 186, 201, 211, 0, 230, 207, 225, 158, 168, 44, 99, 22, 1, 63, 88, 226, 137, 169, 13, 56, 52, 27, 171, 51, 255, 176, 187, 72, 12, 95, 185, 177, 205, 46, 197, 243, 219, 71, 229, 165, 156, 119, 10, 166, 32, 104, 254, 127, 193, 173};
   private final int[] expandedKey = new int[64];
   private int effectiveKeyBits;

   int getBlockSize() {
      return 8;
   }

   int getEffectiveKeyBits() {
      return this.effectiveKeyBits;
   }

   void initEffectiveKeyBits(int var1) {
      this.effectiveKeyBits = var1;
   }

   static void checkKey(String var0, int var1) throws InvalidKeyException {
      if (!var0.equals("RC2")) {
         throw new InvalidKeyException("Key algorithm must be RC2");
      } else if (var1 < 5 || var1 > 128) {
         throw new InvalidKeyException("RC2 key length must be between 40 and 1024 bit");
      }
   }

   void init(boolean var1, String var2, byte[] var3) throws InvalidKeyException {
      int var4 = var3.length;
      if (this.effectiveKeyBits == 0) {
         this.effectiveKeyBits = var4 << 3;
      }

      checkKey(var2, var4);
      byte[] var5 = new byte[128];
      System.arraycopy(var3, 0, var5, 0, var4);
      int var6 = var5[var4 - 1];

      int var7;
      for(var7 = var4; var7 < 128; ++var7) {
         var6 = PI_TABLE[var6 + var5[var7 - var4] & 255];
         var5[var7] = (byte)var6;
      }

      var7 = this.effectiveKeyBits + 7 >> 3;
      int var8 = 255 >> (-this.effectiveKeyBits & 7);
      var6 = PI_TABLE[var5[128 - var7] & var8];
      var5[128 - var7] = (byte)var6;

      int var9;
      for(var9 = 127 - var7; var9 >= 0; --var9) {
         var6 = PI_TABLE[var6 ^ var5[var9 + var7] & 255];
         var5[var9] = (byte)var6;
      }

      var9 = 0;

      for(int var10 = 0; var9 < 64; var10 += 2) {
         var6 = (var5[var10] & 255) + ((var5[var10 + 1] & 255) << 8);
         this.expandedKey[var9] = var6;
         ++var9;
      }

   }

   void encryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      int var5 = (var1[var2] & 255) + ((var1[var2 + 1] & 255) << 8);
      int var6 = (var1[var2 + 2] & 255) + ((var1[var2 + 3] & 255) << 8);
      int var7 = (var1[var2 + 4] & 255) + ((var1[var2 + 5] & 255) << 8);
      int var8 = (var1[var2 + 6] & 255) + ((var1[var2 + 7] & 255) << 8);

      int var9;
      for(var9 = 0; var9 < 20; var9 += 4) {
         var5 = var5 + this.expandedKey[var9] + (var8 & var7) + (~var8 & var6) & '\uffff';
         var5 = var5 << 1 | var5 >>> 15;
         var6 = var6 + this.expandedKey[var9 + 1] + (var5 & var8) + (~var5 & var7) & '\uffff';
         var6 = var6 << 2 | var6 >>> 14;
         var7 = var7 + this.expandedKey[var9 + 2] + (var6 & var5) + (~var6 & var8) & '\uffff';
         var7 = var7 << 3 | var7 >>> 13;
         var8 = var8 + this.expandedKey[var9 + 3] + (var7 & var6) + (~var7 & var5) & '\uffff';
         var8 = var8 << 5 | var8 >>> 11;
      }

      var5 += this.expandedKey[var8 & 63];
      var6 += this.expandedKey[var5 & 63];
      var7 += this.expandedKey[var6 & 63];
      var8 += this.expandedKey[var7 & 63];

      for(var9 = 20; var9 < 44; var9 += 4) {
         var5 = var5 + this.expandedKey[var9] + (var8 & var7) + (~var8 & var6) & '\uffff';
         var5 = var5 << 1 | var5 >>> 15;
         var6 = var6 + this.expandedKey[var9 + 1] + (var5 & var8) + (~var5 & var7) & '\uffff';
         var6 = var6 << 2 | var6 >>> 14;
         var7 = var7 + this.expandedKey[var9 + 2] + (var6 & var5) + (~var6 & var8) & '\uffff';
         var7 = var7 << 3 | var7 >>> 13;
         var8 = var8 + this.expandedKey[var9 + 3] + (var7 & var6) + (~var7 & var5) & '\uffff';
         var8 = var8 << 5 | var8 >>> 11;
      }

      var5 += this.expandedKey[var8 & 63];
      var6 += this.expandedKey[var5 & 63];
      var7 += this.expandedKey[var6 & 63];
      var8 += this.expandedKey[var7 & 63];

      for(var9 = 44; var9 < 64; var9 += 4) {
         var5 = var5 + this.expandedKey[var9] + (var8 & var7) + (~var8 & var6) & '\uffff';
         var5 = var5 << 1 | var5 >>> 15;
         var6 = var6 + this.expandedKey[var9 + 1] + (var5 & var8) + (~var5 & var7) & '\uffff';
         var6 = var6 << 2 | var6 >>> 14;
         var7 = var7 + this.expandedKey[var9 + 2] + (var6 & var5) + (~var6 & var8) & '\uffff';
         var7 = var7 << 3 | var7 >>> 13;
         var8 = var8 + this.expandedKey[var9 + 3] + (var7 & var6) + (~var7 & var5) & '\uffff';
         var8 = var8 << 5 | var8 >>> 11;
      }

      var3[var4] = (byte)var5;
      var3[var4 + 1] = (byte)(var5 >> 8);
      var3[var4 + 2] = (byte)var6;
      var3[var4 + 3] = (byte)(var6 >> 8);
      var3[var4 + 4] = (byte)var7;
      var3[var4 + 5] = (byte)(var7 >> 8);
      var3[var4 + 6] = (byte)var8;
      var3[var4 + 7] = (byte)(var8 >> 8);
   }

   void decryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      int var5 = (var1[var2] & 255) + ((var1[var2 + 1] & 255) << 8);
      int var6 = (var1[var2 + 2] & 255) + ((var1[var2 + 3] & 255) << 8);
      int var7 = (var1[var2 + 4] & 255) + ((var1[var2 + 5] & 255) << 8);
      int var8 = (var1[var2 + 6] & 255) + ((var1[var2 + 7] & 255) << 8);

      int var9;
      for(var9 = 64; var9 > 44; var9 -= 4) {
         var8 = (var8 << 11 | var8 >>> 5) & '\uffff';
         var8 = var8 - this.expandedKey[var9 - 1] - (var7 & var6) - (~var7 & var5) & '\uffff';
         var7 = (var7 << 13 | var7 >>> 3) & '\uffff';
         var7 = var7 - this.expandedKey[var9 - 2] - (var6 & var5) - (~var6 & var8) & '\uffff';
         var6 = (var6 << 14 | var6 >>> 2) & '\uffff';
         var6 = var6 - this.expandedKey[var9 - 3] - (var5 & var8) - (~var5 & var7) & '\uffff';
         var5 = (var5 << 15 | var5 >>> 1) & '\uffff';
         var5 = var5 - this.expandedKey[var9 - 4] - (var8 & var7) - (~var8 & var6) & '\uffff';
      }

      var8 = var8 - this.expandedKey[var7 & 63] & '\uffff';
      var7 = var7 - this.expandedKey[var6 & 63] & '\uffff';
      var6 = var6 - this.expandedKey[var5 & 63] & '\uffff';
      var5 = var5 - this.expandedKey[var8 & 63] & '\uffff';

      for(var9 = 44; var9 > 20; var9 -= 4) {
         var8 = (var8 << 11 | var8 >>> 5) & '\uffff';
         var8 = var8 - this.expandedKey[var9 - 1] - (var7 & var6) - (~var7 & var5) & '\uffff';
         var7 = (var7 << 13 | var7 >>> 3) & '\uffff';
         var7 = var7 - this.expandedKey[var9 - 2] - (var6 & var5) - (~var6 & var8) & '\uffff';
         var6 = (var6 << 14 | var6 >>> 2) & '\uffff';
         var6 = var6 - this.expandedKey[var9 - 3] - (var5 & var8) - (~var5 & var7) & '\uffff';
         var5 = (var5 << 15 | var5 >>> 1) & '\uffff';
         var5 = var5 - this.expandedKey[var9 - 4] - (var8 & var7) - (~var8 & var6) & '\uffff';
      }

      var8 = var8 - this.expandedKey[var7 & 63] & '\uffff';
      var7 = var7 - this.expandedKey[var6 & 63] & '\uffff';
      var6 = var6 - this.expandedKey[var5 & 63] & '\uffff';
      var5 = var5 - this.expandedKey[var8 & 63] & '\uffff';

      for(var9 = 20; var9 > 0; var9 -= 4) {
         var8 = (var8 << 11 | var8 >>> 5) & '\uffff';
         var8 = var8 - this.expandedKey[var9 - 1] - (var7 & var6) - (~var7 & var5) & '\uffff';
         var7 = (var7 << 13 | var7 >>> 3) & '\uffff';
         var7 = var7 - this.expandedKey[var9 - 2] - (var6 & var5) - (~var6 & var8) & '\uffff';
         var6 = (var6 << 14 | var6 >>> 2) & '\uffff';
         var6 = var6 - this.expandedKey[var9 - 3] - (var5 & var8) - (~var5 & var7) & '\uffff';
         var5 = (var5 << 15 | var5 >>> 1) & '\uffff';
         var5 = var5 - this.expandedKey[var9 - 4] - (var8 & var7) - (~var8 & var6) & '\uffff';
      }

      var3[var4] = (byte)var5;
      var3[var4 + 1] = (byte)(var5 >> 8);
      var3[var4 + 2] = (byte)var6;
      var3[var4 + 3] = (byte)(var6 >> 8);
      var3[var4 + 4] = (byte)var7;
      var3[var4 + 5] = (byte)(var7 >> 8);
      var3[var4 + 6] = (byte)var8;
      var3[var4 + 7] = (byte)(var8 >> 8);
   }
}
