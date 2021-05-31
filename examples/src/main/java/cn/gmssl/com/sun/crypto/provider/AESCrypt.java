package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

final class AESCrypt extends SymmetricCipher implements AESConstants {
   private boolean ROUNDS_12 = false;
   private boolean ROUNDS_14 = false;
   private Object[] sessionK = null;
   private int[] K = null;
   private int limit = 0;
   private static int[] alog = new int[256];
   private static int[] log = new int[256];
   private static final byte[] S = new byte[256];
   private static final byte[] Si = new byte[256];
   private static final int[] T1 = new int[256];
   private static final int[] T2 = new int[256];
   private static final int[] T3 = new int[256];
   private static final int[] T4 = new int[256];
   private static final int[] T5 = new int[256];
   private static final int[] T6 = new int[256];
   private static final int[] T7 = new int[256];
   private static final int[] T8 = new int[256];
   private static final int[] U1 = new int[256];
   private static final int[] U2 = new int[256];
   private static final int[] U3 = new int[256];
   private static final int[] U4 = new int[256];
   private static final byte[] rcon = new byte[30];

   static {
      short var0 = 283;
      boolean var2 = false;
      alog[0] = 1;

      int var1;
      int var15;
      for(var1 = 1; var1 < 256; ++var1) {
         var15 = alog[var1 - 1] << 1 ^ alog[var1 - 1];
         if ((var15 & 256) != 0) {
            var15 ^= var0;
         }

         alog[var1] = var15;
      }

      for(var1 = 1; var1 < 255; log[alog[var1]] = var1++) {
         ;
      }

      byte[][] var3 = new byte[][]{{1, 1, 1, 1, 1, 0, 0, 0}, {0, 1, 1, 1, 1, 1, 0, 0}, {0, 0, 1, 1, 1, 1, 1, 0}, {0, 0, 0, 1, 1, 1, 1, 1}, {1, 0, 0, 0, 1, 1, 1, 1}, {1, 1, 0, 0, 0, 1, 1, 1}, {1, 1, 1, 0, 0, 0, 1, 1}, {1, 1, 1, 1, 0, 0, 0, 1}};
      byte[] var4 = new byte[]{0, 1, 1, 0, 0, 0, 1, 1};
      byte[][] var6 = new byte[256][8];
      var6[1][7] = 1;

      int var5;
      for(var1 = 2; var1 < 256; ++var1) {
         var15 = alog[255 - log[var1]];

         for(var5 = 0; var5 < 8; ++var5) {
            var6[var1][var5] = (byte)(var15 >>> 7 - var5 & 1);
         }
      }

      byte[][] var7 = new byte[256][8];

      for(var1 = 0; var1 < 256; ++var1) {
         for(var5 = 0; var5 < 8; ++var5) {
            var7[var1][var5] = var4[var5];

            for(var15 = 0; var15 < 8; ++var15) {
               var7[var1][var5] = (byte)(var7[var1][var5] ^ var3[var5][var15] * var6[var1][var15]);
            }
         }
      }

      for(var1 = 0; var1 < 256; ++var1) {
         S[var1] = (byte)(var7[var1][0] << 7);

         for(var5 = 1; var5 < 8; ++var5) {
            S[var1] = (byte)(S[var1] ^ var7[var1][var5] << 7 - var5);
         }

         Si[S[var1] & 255] = (byte)var1;
      }

      byte[][] var8 = new byte[][]{{2, 1, 1, 3}, {3, 2, 1, 1}, {1, 3, 2, 1}, {1, 1, 3, 2}};
      byte[][] var9 = new byte[4][8];

      for(var1 = 0; var1 < 4; ++var1) {
         for(var15 = 0; var15 < 4; ++var15) {
            var9[var1][var15] = var8[var1][var15];
         }

         var9[var1][var1 + 4] = 1;
      }

      byte[][] var12 = new byte[4][4];

      for(var1 = 0; var1 < 4; ++var1) {
         byte var10 = var9[var1][var1];
         if (var10 == 0) {
            for(var5 = var1 + 1; var9[var5][var1] == 0 && var5 < 4; ++var5) {
               ;
            }

            if (var5 == 4) {
               throw new RuntimeException("G matrix is not invertible");
            }

            for(var15 = 0; var15 < 8; ++var15) {
               byte var11 = var9[var1][var15];
               var9[var1][var15] = var9[var5][var15];
               var9[var5][var15] = var11;
            }

            var10 = var9[var1][var1];
         }

         for(var15 = 0; var15 < 8; ++var15) {
            if (var9[var1][var15] != 0) {
               var9[var1][var15] = (byte)alog[(255 + log[var9[var1][var15] & 255] - log[var10 & 255]) % 255];
            }
         }

         for(var5 = 0; var5 < 4; ++var5) {
            if (var1 != var5) {
               for(var15 = var1 + 1; var15 < 8; ++var15) {
                  var9[var5][var15] = (byte)(var9[var5][var15] ^ mul(var9[var1][var15], var9[var5][var1]));
               }

               var9[var5][var1] = 0;
            }
         }
      }

      for(var1 = 0; var1 < 4; ++var1) {
         for(var15 = 0; var15 < 4; ++var15) {
            var12[var1][var15] = var9[var1][var15 + 4];
         }
      }

      for(var5 = 0; var5 < 256; ++var5) {
         byte var13 = S[var5];
         T1[var5] = mul4(var13, var8[0]);
         T2[var5] = mul4(var13, var8[1]);
         T3[var5] = mul4(var13, var8[2]);
         T4[var5] = mul4(var13, var8[3]);
         var13 = Si[var5];
         T5[var5] = mul4(var13, var12[0]);
         T6[var5] = mul4(var13, var12[1]);
         T7[var5] = mul4(var13, var12[2]);
         T8[var5] = mul4(var13, var12[3]);
         U1[var5] = mul4(var5, var12[0]);
         U2[var5] = mul4(var5, var12[1]);
         U3[var5] = mul4(var5, var12[2]);
         U4[var5] = mul4(var5, var12[3]);
      }

      rcon[0] = 1;
      int var14 = 1;

      for(var5 = 1; var5 < 30; ++var5) {
         var14 = mul(2, var14);
         rcon[var5] = (byte)var14;
      }

      log = null;
      alog = null;
   }

   int getBlockSize() {
      return 16;
   }

   void init(boolean var1, String var2, byte[] var3) throws InvalidKeyException {
      if (!var2.equalsIgnoreCase("AES") && !var2.equalsIgnoreCase("Rijndael")) {
         throw new InvalidKeyException("Wrong algorithm: AES or Rijndael required");
      } else if (!isKeySizeValid(var3.length)) {
         throw new InvalidKeyException("Invalid AES key length: " + var3.length + " bytes");
      } else {
         this.sessionK = makeKey(var3);
         this.setSubKey(var1);
      }
   }

   private void setSubKey(boolean var1) {
      int[][] var2 = (int[][])this.sessionK[var1 ? 1 : 0];
      int var3 = var2.length;
      this.K = new int[var3 * 4];

      int var4;
      int var5;
      for(var4 = 0; var4 < var3; ++var4) {
         for(var5 = 0; var5 < 4; ++var5) {
            this.K[var4 * 4 + var5] = var2[var4][var5];
         }
      }

      if (var1) {
         var4 = this.K[this.K.length - 4];
         var5 = this.K[this.K.length - 3];
         int var6 = this.K[this.K.length - 2];
         int var7 = this.K[this.K.length - 1];

         for(int var8 = this.K.length - 1; var8 > 3; --var8) {
            this.K[var8] = this.K[var8 - 4];
         }

         this.K[0] = var4;
         this.K[1] = var5;
         this.K[2] = var6;
         this.K[3] = var7;
      }

      this.ROUNDS_12 = var3 >= 13;
      this.ROUNDS_14 = var3 == 15;
      --var3;
      this.limit = var3 * 4;
   }

   private static final int mul(int var0, int var1) {
      return var0 != 0 && var1 != 0 ? alog[(log[var0 & 255] + log[var1 & 255]) % 255] : 0;
   }

   private static final int mul4(int var0, byte[] var1) {
      if (var0 == 0) {
         return 0;
      } else {
         var0 = log[var0 & 255];
         int var2 = var1[0] != 0 ? alog[(var0 + log[var1[0] & 255]) % 255] & 255 : 0;
         int var3 = var1[1] != 0 ? alog[(var0 + log[var1[1] & 255]) % 255] & 255 : 0;
         int var4 = var1[2] != 0 ? alog[(var0 + log[var1[2] & 255]) % 255] & 255 : 0;
         int var5 = var1[3] != 0 ? alog[(var0 + log[var1[3] & 255]) % 255] & 255 : 0;
         return var2 << 24 | var3 << 16 | var4 << 8 | var5;
      }
   }

   static final boolean isKeySizeValid(int var0) {
      for(int var1 = 0; var1 < AES_KEYSIZES.length; ++var1) {
         if (var0 == AES_KEYSIZES[var1]) {
            return true;
         }
      }

      return false;
   }

   void encryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      byte var5 = 0;
      int var10000 = var1[var2++] << 24 | (var1[var2++] & 255) << 16 | (var1[var2++] & 255) << 8 | var1[var2++] & 255;
      int var13 = var5 + 1;
      int var6 = var10000 ^ this.K[var5];
      int var7 = (var1[var2++] << 24 | (var1[var2++] & 255) << 16 | (var1[var2++] & 255) << 8 | var1[var2++] & 255) ^ this.K[var13++];
      int var8 = (var1[var2++] << 24 | (var1[var2++] & 255) << 16 | (var1[var2++] & 255) << 8 | var1[var2++] & 255) ^ this.K[var13++];

      int var9;
      int var10;
      int var12;
      for(var9 = (var1[var2++] << 24 | (var1[var2++] & 255) << 16 | (var1[var2++] & 255) << 8 | var1[var2++] & 255) ^ this.K[var13++]; var13 < this.limit; var8 = var12) {
         var10 = T1[var6 >>> 24] ^ T2[var7 >>> 16 & 255] ^ T3[var8 >>> 8 & 255] ^ T4[var9 & 255] ^ this.K[var13++];
         int var11 = T1[var7 >>> 24] ^ T2[var8 >>> 16 & 255] ^ T3[var9 >>> 8 & 255] ^ T4[var6 & 255] ^ this.K[var13++];
         var12 = T1[var8 >>> 24] ^ T2[var9 >>> 16 & 255] ^ T3[var6 >>> 8 & 255] ^ T4[var7 & 255] ^ this.K[var13++];
         var9 = T1[var9 >>> 24] ^ T2[var6 >>> 16 & 255] ^ T3[var7 >>> 8 & 255] ^ T4[var8 & 255] ^ this.K[var13++];
         var6 = var10;
         var7 = var11;
      }

      var10 = this.K[var13++];
      var3[var4++] = (byte)(S[var6 >>> 24] ^ var10 >>> 24);
      var3[var4++] = (byte)(S[var7 >>> 16 & 255] ^ var10 >>> 16);
      var3[var4++] = (byte)(S[var8 >>> 8 & 255] ^ var10 >>> 8);
      var3[var4++] = (byte)(S[var9 & 255] ^ var10);
      var10 = this.K[var13++];
      var3[var4++] = (byte)(S[var7 >>> 24] ^ var10 >>> 24);
      var3[var4++] = (byte)(S[var8 >>> 16 & 255] ^ var10 >>> 16);
      var3[var4++] = (byte)(S[var9 >>> 8 & 255] ^ var10 >>> 8);
      var3[var4++] = (byte)(S[var6 & 255] ^ var10);
      var10 = this.K[var13++];
      var3[var4++] = (byte)(S[var8 >>> 24] ^ var10 >>> 24);
      var3[var4++] = (byte)(S[var9 >>> 16 & 255] ^ var10 >>> 16);
      var3[var4++] = (byte)(S[var6 >>> 8 & 255] ^ var10 >>> 8);
      var3[var4++] = (byte)(S[var7 & 255] ^ var10);
      var10 = this.K[var13++];
      var3[var4++] = (byte)(S[var9 >>> 24] ^ var10 >>> 24);
      var3[var4++] = (byte)(S[var6 >>> 16 & 255] ^ var10 >>> 16);
      var3[var4++] = (byte)(S[var7 >>> 8 & 255] ^ var10 >>> 8);
      var3[var4] = (byte)(S[var8 & 255] ^ var10);
   }

   void decryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      byte var5 = 4;
      int var10000 = var1[var2++] << 24 | (var1[var2++] & 255) << 16 | (var1[var2++] & 255) << 8 | var1[var2++] & 255;
      int var13 = var5 + 1;
      int var6 = var10000 ^ this.K[var5];
      int var7 = (var1[var2++] << 24 | (var1[var2++] & 255) << 16 | (var1[var2++] & 255) << 8 | var1[var2++] & 255) ^ this.K[var13++];
      int var8 = (var1[var2++] << 24 | (var1[var2++] & 255) << 16 | (var1[var2++] & 255) << 8 | var1[var2++] & 255) ^ this.K[var13++];
      int var9 = (var1[var2++] << 24 | (var1[var2++] & 255) << 16 | (var1[var2++] & 255) << 8 | var1[var2] & 255) ^ this.K[var13++];
      int var10;
      int var11;
      int var12;
      if (this.ROUNDS_12) {
         var10 = T5[var6 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var8 >>> 8 & 255] ^ T8[var7 & 255] ^ this.K[var13++];
         var11 = T5[var7 >>> 24] ^ T6[var6 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var8 & 255] ^ this.K[var13++];
         var12 = T5[var8 >>> 24] ^ T6[var7 >>> 16 & 255] ^ T7[var6 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
         var9 = T5[var9 >>> 24] ^ T6[var8 >>> 16 & 255] ^ T7[var7 >>> 8 & 255] ^ T8[var6 & 255] ^ this.K[var13++];
         var6 = T5[var10 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var12 >>> 8 & 255] ^ T8[var11 & 255] ^ this.K[var13++];
         var7 = T5[var11 >>> 24] ^ T6[var10 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var12 & 255] ^ this.K[var13++];
         var8 = T5[var12 >>> 24] ^ T6[var11 >>> 16 & 255] ^ T7[var10 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
         var9 = T5[var9 >>> 24] ^ T6[var12 >>> 16 & 255] ^ T7[var11 >>> 8 & 255] ^ T8[var10 & 255] ^ this.K[var13++];
         if (this.ROUNDS_14) {
            var10 = T5[var6 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var8 >>> 8 & 255] ^ T8[var7 & 255] ^ this.K[var13++];
            var11 = T5[var7 >>> 24] ^ T6[var6 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var8 & 255] ^ this.K[var13++];
            var12 = T5[var8 >>> 24] ^ T6[var7 >>> 16 & 255] ^ T7[var6 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
            var9 = T5[var9 >>> 24] ^ T6[var8 >>> 16 & 255] ^ T7[var7 >>> 8 & 255] ^ T8[var6 & 255] ^ this.K[var13++];
            var6 = T5[var10 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var12 >>> 8 & 255] ^ T8[var11 & 255] ^ this.K[var13++];
            var7 = T5[var11 >>> 24] ^ T6[var10 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var12 & 255] ^ this.K[var13++];
            var8 = T5[var12 >>> 24] ^ T6[var11 >>> 16 & 255] ^ T7[var10 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
            var9 = T5[var9 >>> 24] ^ T6[var12 >>> 16 & 255] ^ T7[var11 >>> 8 & 255] ^ T8[var10 & 255] ^ this.K[var13++];
         }
      }

      var10 = T5[var6 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var8 >>> 8 & 255] ^ T8[var7 & 255] ^ this.K[var13++];
      var11 = T5[var7 >>> 24] ^ T6[var6 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var8 & 255] ^ this.K[var13++];
      var12 = T5[var8 >>> 24] ^ T6[var7 >>> 16 & 255] ^ T7[var6 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
      var9 = T5[var9 >>> 24] ^ T6[var8 >>> 16 & 255] ^ T7[var7 >>> 8 & 255] ^ T8[var6 & 255] ^ this.K[var13++];
      var6 = T5[var10 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var12 >>> 8 & 255] ^ T8[var11 & 255] ^ this.K[var13++];
      var7 = T5[var11 >>> 24] ^ T6[var10 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var12 & 255] ^ this.K[var13++];
      var8 = T5[var12 >>> 24] ^ T6[var11 >>> 16 & 255] ^ T7[var10 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
      var9 = T5[var9 >>> 24] ^ T6[var12 >>> 16 & 255] ^ T7[var11 >>> 8 & 255] ^ T8[var10 & 255] ^ this.K[var13++];
      var10 = T5[var6 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var8 >>> 8 & 255] ^ T8[var7 & 255] ^ this.K[var13++];
      var11 = T5[var7 >>> 24] ^ T6[var6 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var8 & 255] ^ this.K[var13++];
      var12 = T5[var8 >>> 24] ^ T6[var7 >>> 16 & 255] ^ T7[var6 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
      var9 = T5[var9 >>> 24] ^ T6[var8 >>> 16 & 255] ^ T7[var7 >>> 8 & 255] ^ T8[var6 & 255] ^ this.K[var13++];
      var6 = T5[var10 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var12 >>> 8 & 255] ^ T8[var11 & 255] ^ this.K[var13++];
      var7 = T5[var11 >>> 24] ^ T6[var10 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var12 & 255] ^ this.K[var13++];
      var8 = T5[var12 >>> 24] ^ T6[var11 >>> 16 & 255] ^ T7[var10 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
      var9 = T5[var9 >>> 24] ^ T6[var12 >>> 16 & 255] ^ T7[var11 >>> 8 & 255] ^ T8[var10 & 255] ^ this.K[var13++];
      var10 = T5[var6 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var8 >>> 8 & 255] ^ T8[var7 & 255] ^ this.K[var13++];
      var11 = T5[var7 >>> 24] ^ T6[var6 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var8 & 255] ^ this.K[var13++];
      var12 = T5[var8 >>> 24] ^ T6[var7 >>> 16 & 255] ^ T7[var6 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
      var9 = T5[var9 >>> 24] ^ T6[var8 >>> 16 & 255] ^ T7[var7 >>> 8 & 255] ^ T8[var6 & 255] ^ this.K[var13++];
      var6 = T5[var10 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var12 >>> 8 & 255] ^ T8[var11 & 255] ^ this.K[var13++];
      var7 = T5[var11 >>> 24] ^ T6[var10 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var12 & 255] ^ this.K[var13++];
      var8 = T5[var12 >>> 24] ^ T6[var11 >>> 16 & 255] ^ T7[var10 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
      var9 = T5[var9 >>> 24] ^ T6[var12 >>> 16 & 255] ^ T7[var11 >>> 8 & 255] ^ T8[var10 & 255] ^ this.K[var13++];
      var10 = T5[var6 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var8 >>> 8 & 255] ^ T8[var7 & 255] ^ this.K[var13++];
      var11 = T5[var7 >>> 24] ^ T6[var6 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var8 & 255] ^ this.K[var13++];
      var12 = T5[var8 >>> 24] ^ T6[var7 >>> 16 & 255] ^ T7[var6 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
      var9 = T5[var9 >>> 24] ^ T6[var8 >>> 16 & 255] ^ T7[var7 >>> 8 & 255] ^ T8[var6 & 255] ^ this.K[var13++];
      var6 = T5[var10 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var12 >>> 8 & 255] ^ T8[var11 & 255] ^ this.K[var13++];
      var7 = T5[var11 >>> 24] ^ T6[var10 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var12 & 255] ^ this.K[var13++];
      var8 = T5[var12 >>> 24] ^ T6[var11 >>> 16 & 255] ^ T7[var10 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
      var9 = T5[var9 >>> 24] ^ T6[var12 >>> 16 & 255] ^ T7[var11 >>> 8 & 255] ^ T8[var10 & 255] ^ this.K[var13++];
      var10 = T5[var6 >>> 24] ^ T6[var9 >>> 16 & 255] ^ T7[var8 >>> 8 & 255] ^ T8[var7 & 255] ^ this.K[var13++];
      var11 = T5[var7 >>> 24] ^ T6[var6 >>> 16 & 255] ^ T7[var9 >>> 8 & 255] ^ T8[var8 & 255] ^ this.K[var13++];
      var12 = T5[var8 >>> 24] ^ T6[var7 >>> 16 & 255] ^ T7[var6 >>> 8 & 255] ^ T8[var9 & 255] ^ this.K[var13++];
      var9 = T5[var9 >>> 24] ^ T6[var8 >>> 16 & 255] ^ T7[var7 >>> 8 & 255] ^ T8[var6 & 255] ^ this.K[var13++];
      var7 = this.K[0];
      var3[var4++] = (byte)(Si[var10 >>> 24] ^ var7 >>> 24);
      var3[var4++] = (byte)(Si[var9 >>> 16 & 255] ^ var7 >>> 16);
      var3[var4++] = (byte)(Si[var12 >>> 8 & 255] ^ var7 >>> 8);
      var3[var4++] = (byte)(Si[var11 & 255] ^ var7);
      var7 = this.K[1];
      var3[var4++] = (byte)(Si[var11 >>> 24] ^ var7 >>> 24);
      var3[var4++] = (byte)(Si[var10 >>> 16 & 255] ^ var7 >>> 16);
      var3[var4++] = (byte)(Si[var9 >>> 8 & 255] ^ var7 >>> 8);
      var3[var4++] = (byte)(Si[var12 & 255] ^ var7);
      var7 = this.K[2];
      var3[var4++] = (byte)(Si[var12 >>> 24] ^ var7 >>> 24);
      var3[var4++] = (byte)(Si[var11 >>> 16 & 255] ^ var7 >>> 16);
      var3[var4++] = (byte)(Si[var10 >>> 8 & 255] ^ var7 >>> 8);
      var3[var4++] = (byte)(Si[var9 & 255] ^ var7);
      var7 = this.K[3];
      var3[var4++] = (byte)(Si[var9 >>> 24] ^ var7 >>> 24);
      var3[var4++] = (byte)(Si[var12 >>> 16 & 255] ^ var7 >>> 16);
      var3[var4++] = (byte)(Si[var11 >>> 8 & 255] ^ var7 >>> 8);
      var3[var4] = (byte)(Si[var10 & 255] ^ var7);
   }

   private static Object[] makeKey(byte[] var0) throws InvalidKeyException {
      if (var0 == null) {
         throw new InvalidKeyException("Empty key");
      } else if (!isKeySizeValid(var0.length)) {
         throw new InvalidKeyException("Invalid AES key length: " + var0.length + " bytes");
      } else {
         int var1 = getRounds(var0.length);
         int var2 = (var1 + 1) * 4;
         byte var3 = 4;
         int[][] var4 = new int[var1 + 1][4];
         int[][] var5 = new int[var1 + 1][4];
         int var6 = var0.length / 4;
         int[] var7 = new int[var6];
         int var8 = 0;

         int var9;
         for(var9 = 0; var8 < var6; var9 += 4) {
            var7[var8] = var0[var9] << 24 | (var0[var9 + 1] & 255) << 16 | (var0[var9 + 2] & 255) << 8 | var0[var9 + 3] & 255;
            ++var8;
         }

         int var10 = 0;

         for(var9 = 0; var9 < var6 && var10 < var2; ++var10) {
            var4[var10 / 4][var10 % 4] = var7[var9];
            var5[var1 - var10 / 4][var10 % 4] = var7[var9];
            ++var9;
         }

         int var12 = 0;

         int var11;
         while(var10 < var2) {
            var11 = var7[var6 - 1];
            var7[0] ^= S[var11 >>> 16 & 255] << 24 ^ (S[var11 >>> 8 & 255] & 255) << 16 ^ (S[var11 & 255] & 255) << 8 ^ S[var11 >>> 24] & 255 ^ rcon[var12++] << 24;
            if (var6 != 8) {
               var8 = 1;

               for(var9 = 0; var8 < var6; ++var9) {
                  var7[var8] ^= var7[var9];
                  ++var8;
               }
            } else {
               var8 = 1;

               for(var9 = 0; var8 < var6 / 2; ++var9) {
                  var7[var8] ^= var7[var9];
                  ++var8;
               }

               var11 = var7[var6 / 2 - 1];
               var7[var6 / 2] ^= S[var11 & 255] & 255 ^ (S[var11 >>> 8 & 255] & 255) << 8 ^ (S[var11 >>> 16 & 255] & 255) << 16 ^ S[var11 >>> 24] << 24;
               var9 = var6 / 2;

               for(var8 = var9 + 1; var8 < var6; ++var9) {
                  var7[var8] ^= var7[var9];
                  ++var8;
               }
            }

            for(var9 = 0; var9 < var6 && var10 < var2; ++var10) {
               var4[var10 / 4][var10 % 4] = var7[var9];
               var5[var1 - var10 / 4][var10 % 4] = var7[var9];
               ++var9;
            }
         }

         for(int var13 = 1; var13 < var1; ++var13) {
            for(var9 = 0; var9 < var3; ++var9) {
               var11 = var5[var13][var9];
               var5[var13][var9] = U1[var11 >>> 24 & 255] ^ U2[var11 >>> 16 & 255] ^ U3[var11 >>> 8 & 255] ^ U4[var11 & 255];
            }
         }

         Object[] var14 = new Object[]{var4, var5};
         return var14;
      }
   }

   private static int getRounds(int var0) {
      return (var0 >> 2) + 6;
   }
}
