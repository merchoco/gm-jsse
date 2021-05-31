package org.bc.crypto.engines;

import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.params.KeyParameter;

public class AESLightEngine implements BlockCipher {
   private static final byte[] S = new byte[]{99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 103, 43, -2, -41, -85, 118, -54, -126, -55, 125, -6, 89, 71, -16, -83, -44, -94, -81, -100, -92, 114, -64, -73, -3, -109, 38, 54, 63, -9, -52, 52, -91, -27, -15, 113, -40, 49, 21, 4, -57, 35, -61, 24, -106, 5, -102, 7, 18, -128, -30, -21, 39, -78, 117, 9, -125, 44, 26, 27, 110, 90, -96, 82, 59, -42, -77, 41, -29, 47, -124, 83, -47, 0, -19, 32, -4, -79, 91, 106, -53, -66, 57, 74, 76, 88, -49, -48, -17, -86, -5, 67, 77, 51, -123, 69, -7, 2, 127, 80, 60, -97, -88, 81, -93, 64, -113, -110, -99, 56, -11, -68, -74, -38, 33, 16, -1, -13, -46, -51, 12, 19, -20, 95, -105, 68, 23, -60, -89, 126, 61, 100, 93, 25, 115, 96, -127, 79, -36, 34, 42, -112, -120, 70, -18, -72, 20, -34, 94, 11, -37, -32, 50, 58, 10, 73, 6, 36, 92, -62, -45, -84, 98, -111, -107, -28, 121, -25, -56, 55, 109, -115, -43, 78, -87, 108, 86, -12, -22, 101, 122, -82, 8, -70, 120, 37, 46, 28, -90, -76, -58, -24, -35, 116, 31, 75, -67, -117, -118, 112, 62, -75, 102, 72, 3, -10, 14, 97, 53, 87, -71, -122, -63, 29, -98, -31, -8, -104, 17, 105, -39, -114, -108, -101, 30, -121, -23, -50, 85, 40, -33, -116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 45, 15, -80, 84, -69, 22};
   private static final byte[] Si = new byte[]{82, 9, 106, -43, 48, 54, -91, 56, -65, 64, -93, -98, -127, -13, -41, -5, 124, -29, 57, -126, -101, 47, -1, -121, 52, -114, 67, 68, -60, -34, -23, -53, 84, 123, -108, 50, -90, -62, 35, 61, -18, 76, -107, 11, 66, -6, -61, 78, 8, 46, -95, 102, 40, -39, 36, -78, 118, 91, -94, 73, 109, -117, -47, 37, 114, -8, -10, 100, -122, 104, -104, 22, -44, -92, 92, -52, 93, 101, -74, -110, 108, 112, 72, 80, -3, -19, -71, -38, 94, 21, 70, 87, -89, -115, -99, -124, -112, -40, -85, 0, -116, -68, -45, 10, -9, -28, 88, 5, -72, -77, 69, 6, -48, 44, 30, -113, -54, 63, 15, 2, -63, -81, -67, 3, 1, 19, -118, 107, 58, -111, 17, 65, 79, 103, -36, -22, -105, -14, -49, -50, -16, -76, -26, 115, -106, -84, 116, 34, -25, -83, 53, -123, -30, -7, 55, -24, 28, 117, -33, 110, 71, -15, 26, 113, 29, 41, -59, -119, 111, -73, 98, 14, -86, 24, -66, 27, -4, 86, 62, 75, -58, -46, 121, 32, -102, -37, -64, -2, 120, -51, 90, -12, 31, -35, -88, 51, -120, 7, -57, 49, -79, 18, 16, 89, 39, -128, -20, 95, 96, 81, 127, -87, 25, -75, 74, 13, 45, -27, 122, -97, -109, -55, -100, -17, -96, -32, 59, 77, -82, 42, -11, -80, -56, -21, -69, 60, -125, 83, -103, 97, 23, 43, 4, 126, -70, 119, -42, 38, -31, 105, 20, 99, 85, 33, 12, 125};
   private static final int[] rcon = new int[]{1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145};
   private static final int m1 = -2139062144;
   private static final int m2 = 2139062143;
   private static final int m3 = 27;
   private int ROUNDS;
   private int[][] WorkingKey = null;
   private int C0;
   private int C1;
   private int C2;
   private int C3;
   private boolean forEncryption;
   private static final int BLOCK_SIZE = 16;

   private static int shift(int var0, int var1) {
      return var0 >>> var1 | var0 << -var1;
   }

   private static int FFmulX(int var0) {
      return (var0 & 2139062143) << 1 ^ ((var0 & -2139062144) >>> 7) * 27;
   }

   private static int mcol(int var0) {
      int var1 = FFmulX(var0);
      return var1 ^ shift(var0 ^ var1, 8) ^ shift(var0, 16) ^ shift(var0, 24);
   }

   private static int inv_mcol(int var0) {
      int var1 = FFmulX(var0);
      int var2 = FFmulX(var1);
      int var3 = FFmulX(var2);
      int var4 = var0 ^ var3;
      return var1 ^ var2 ^ var3 ^ shift(var1 ^ var4, 8) ^ shift(var2 ^ var4, 16) ^ shift(var4, 24);
   }

   private static int subWord(int var0) {
      return S[var0 & 255] & 255 | (S[var0 >> 8 & 255] & 255) << 8 | (S[var0 >> 16 & 255] & 255) << 16 | S[var0 >> 24 & 255] << 24;
   }

   private int[][] generateWorkingKey(byte[] var1, boolean var2) {
      int var3 = var1.length / 4;
      if ((var3 == 4 || var3 == 6 || var3 == 8) && var3 * 4 == var1.length) {
         this.ROUNDS = var3 + 6;
         int[][] var5 = new int[this.ROUNDS + 1][4];
         int var4 = 0;

         int var6;
         for(var6 = 0; var6 < var1.length; ++var4) {
            var5[var4 >> 2][var4 & 3] = var1[var6] & 255 | (var1[var6 + 1] & 255) << 8 | (var1[var6 + 2] & 255) << 16 | var1[var6 + 3] << 24;
            var6 += 4;
         }

         int var7 = this.ROUNDS + 1 << 2;

         int var8;
         for(var6 = var3; var6 < var7; ++var6) {
            var8 = var5[var6 - 1 >> 2][var6 - 1 & 3];
            if (var6 % var3 == 0) {
               var8 = subWord(shift(var8, 8)) ^ rcon[var6 / var3 - 1];
            } else if (var3 > 6 && var6 % var3 == 4) {
               var8 = subWord(var8);
            }

            var5[var6 >> 2][var6 & 3] = var5[var6 - var3 >> 2][var6 - var3 & 3] ^ var8;
         }

         if (!var2) {
            for(var8 = 1; var8 < this.ROUNDS; ++var8) {
               for(var6 = 0; var6 < 4; ++var6) {
                  var5[var8][var6] = inv_mcol(var5[var8][var6]);
               }
            }
         }

         return var5;
      } else {
         throw new IllegalArgumentException("Key length not 128/192/256 bits.");
      }
   }

   public void init(boolean var1, CipherParameters var2) {
      if (var2 instanceof KeyParameter) {
         this.WorkingKey = this.generateWorkingKey(((KeyParameter)var2).getKey(), var1);
         this.forEncryption = var1;
      } else {
         throw new IllegalArgumentException("invalid parameter passed to AES init - " + var2.getClass().getName());
      }
   }

   public String getAlgorithmName() {
      return "AES";
   }

   public int getBlockSize() {
      return 16;
   }

   public int processBlock(byte[] var1, int var2, byte[] var3, int var4) {
      if (this.WorkingKey == null) {
         throw new IllegalStateException("AES engine not initialised");
      } else if (var2 + 16 > var1.length) {
         throw new DataLengthException("input buffer too short");
      } else if (var4 + 16 > var3.length) {
         throw new DataLengthException("output buffer too short");
      } else {
         if (this.forEncryption) {
            this.unpackBlock(var1, var2);
            this.encryptBlock(this.WorkingKey);
            this.packBlock(var3, var4);
         } else {
            this.unpackBlock(var1, var2);
            this.decryptBlock(this.WorkingKey);
            this.packBlock(var3, var4);
         }

         return 16;
      }
   }

   public void reset() {
   }

   private void unpackBlock(byte[] var1, int var2) {
      int var3 = var2 + 1;
      this.C0 = var1[var2] & 255;
      this.C0 |= (var1[var3++] & 255) << 8;
      this.C0 |= (var1[var3++] & 255) << 16;
      this.C0 |= var1[var3++] << 24;
      this.C1 = var1[var3++] & 255;
      this.C1 |= (var1[var3++] & 255) << 8;
      this.C1 |= (var1[var3++] & 255) << 16;
      this.C1 |= var1[var3++] << 24;
      this.C2 = var1[var3++] & 255;
      this.C2 |= (var1[var3++] & 255) << 8;
      this.C2 |= (var1[var3++] & 255) << 16;
      this.C2 |= var1[var3++] << 24;
      this.C3 = var1[var3++] & 255;
      this.C3 |= (var1[var3++] & 255) << 8;
      this.C3 |= (var1[var3++] & 255) << 16;
      this.C3 |= var1[var3++] << 24;
   }

   private void packBlock(byte[] var1, int var2) {
      int var3 = var2 + 1;
      var1[var2] = (byte)this.C0;
      var1[var3++] = (byte)(this.C0 >> 8);
      var1[var3++] = (byte)(this.C0 >> 16);
      var1[var3++] = (byte)(this.C0 >> 24);
      var1[var3++] = (byte)this.C1;
      var1[var3++] = (byte)(this.C1 >> 8);
      var1[var3++] = (byte)(this.C1 >> 16);
      var1[var3++] = (byte)(this.C1 >> 24);
      var1[var3++] = (byte)this.C2;
      var1[var3++] = (byte)(this.C2 >> 8);
      var1[var3++] = (byte)(this.C2 >> 16);
      var1[var3++] = (byte)(this.C2 >> 24);
      var1[var3++] = (byte)this.C3;
      var1[var3++] = (byte)(this.C3 >> 8);
      var1[var3++] = (byte)(this.C3 >> 16);
      var1[var3++] = (byte)(this.C3 >> 24);
   }

   private void encryptBlock(int[][] var1) {
      this.C0 ^= var1[0][0];
      this.C1 ^= var1[0][1];
      this.C2 ^= var1[0][2];
      this.C3 ^= var1[0][3];

      int var2;
      int var3;
      int var4;
      int var5;
      int var6;
      for(var2 = 1; var2 < this.ROUNDS - 1; this.C3 = mcol(S[var6 & 255] & 255 ^ (S[var3 >> 8 & 255] & 255) << 8 ^ (S[var4 >> 16 & 255] & 255) << 16 ^ S[var5 >> 24 & 255] << 24) ^ var1[var2++][3]) {
         var3 = mcol(S[this.C0 & 255] & 255 ^ (S[this.C1 >> 8 & 255] & 255) << 8 ^ (S[this.C2 >> 16 & 255] & 255) << 16 ^ S[this.C3 >> 24 & 255] << 24) ^ var1[var2][0];
         var4 = mcol(S[this.C1 & 255] & 255 ^ (S[this.C2 >> 8 & 255] & 255) << 8 ^ (S[this.C3 >> 16 & 255] & 255) << 16 ^ S[this.C0 >> 24 & 255] << 24) ^ var1[var2][1];
         var5 = mcol(S[this.C2 & 255] & 255 ^ (S[this.C3 >> 8 & 255] & 255) << 8 ^ (S[this.C0 >> 16 & 255] & 255) << 16 ^ S[this.C1 >> 24 & 255] << 24) ^ var1[var2][2];
         var6 = mcol(S[this.C3 & 255] & 255 ^ (S[this.C0 >> 8 & 255] & 255) << 8 ^ (S[this.C1 >> 16 & 255] & 255) << 16 ^ S[this.C2 >> 24 & 255] << 24) ^ var1[var2++][3];
         this.C0 = mcol(S[var3 & 255] & 255 ^ (S[var4 >> 8 & 255] & 255) << 8 ^ (S[var5 >> 16 & 255] & 255) << 16 ^ S[var6 >> 24 & 255] << 24) ^ var1[var2][0];
         this.C1 = mcol(S[var4 & 255] & 255 ^ (S[var5 >> 8 & 255] & 255) << 8 ^ (S[var6 >> 16 & 255] & 255) << 16 ^ S[var3 >> 24 & 255] << 24) ^ var1[var2][1];
         this.C2 = mcol(S[var5 & 255] & 255 ^ (S[var6 >> 8 & 255] & 255) << 8 ^ (S[var3 >> 16 & 255] & 255) << 16 ^ S[var4 >> 24 & 255] << 24) ^ var1[var2][2];
      }

      var3 = mcol(S[this.C0 & 255] & 255 ^ (S[this.C1 >> 8 & 255] & 255) << 8 ^ (S[this.C2 >> 16 & 255] & 255) << 16 ^ S[this.C3 >> 24 & 255] << 24) ^ var1[var2][0];
      var4 = mcol(S[this.C1 & 255] & 255 ^ (S[this.C2 >> 8 & 255] & 255) << 8 ^ (S[this.C3 >> 16 & 255] & 255) << 16 ^ S[this.C0 >> 24 & 255] << 24) ^ var1[var2][1];
      var5 = mcol(S[this.C2 & 255] & 255 ^ (S[this.C3 >> 8 & 255] & 255) << 8 ^ (S[this.C0 >> 16 & 255] & 255) << 16 ^ S[this.C1 >> 24 & 255] << 24) ^ var1[var2][2];
      var6 = mcol(S[this.C3 & 255] & 255 ^ (S[this.C0 >> 8 & 255] & 255) << 8 ^ (S[this.C1 >> 16 & 255] & 255) << 16 ^ S[this.C2 >> 24 & 255] << 24) ^ var1[var2++][3];
      this.C0 = S[var3 & 255] & 255 ^ (S[var4 >> 8 & 255] & 255) << 8 ^ (S[var5 >> 16 & 255] & 255) << 16 ^ S[var6 >> 24 & 255] << 24 ^ var1[var2][0];
      this.C1 = S[var4 & 255] & 255 ^ (S[var5 >> 8 & 255] & 255) << 8 ^ (S[var6 >> 16 & 255] & 255) << 16 ^ S[var3 >> 24 & 255] << 24 ^ var1[var2][1];
      this.C2 = S[var5 & 255] & 255 ^ (S[var6 >> 8 & 255] & 255) << 8 ^ (S[var3 >> 16 & 255] & 255) << 16 ^ S[var4 >> 24 & 255] << 24 ^ var1[var2][2];
      this.C3 = S[var6 & 255] & 255 ^ (S[var3 >> 8 & 255] & 255) << 8 ^ (S[var4 >> 16 & 255] & 255) << 16 ^ S[var5 >> 24 & 255] << 24 ^ var1[var2][3];
   }

   private void decryptBlock(int[][] var1) {
      this.C0 ^= var1[this.ROUNDS][0];
      this.C1 ^= var1[this.ROUNDS][1];
      this.C2 ^= var1[this.ROUNDS][2];
      this.C3 ^= var1[this.ROUNDS][3];

      int var2;
      int var3;
      int var4;
      int var5;
      int var6;
      for(var2 = this.ROUNDS - 1; var2 > 1; this.C3 = inv_mcol(Si[var6 & 255] & 255 ^ (Si[var5 >> 8 & 255] & 255) << 8 ^ (Si[var4 >> 16 & 255] & 255) << 16 ^ Si[var3 >> 24 & 255] << 24) ^ var1[var2--][3]) {
         var3 = inv_mcol(Si[this.C0 & 255] & 255 ^ (Si[this.C3 >> 8 & 255] & 255) << 8 ^ (Si[this.C2 >> 16 & 255] & 255) << 16 ^ Si[this.C1 >> 24 & 255] << 24) ^ var1[var2][0];
         var4 = inv_mcol(Si[this.C1 & 255] & 255 ^ (Si[this.C0 >> 8 & 255] & 255) << 8 ^ (Si[this.C3 >> 16 & 255] & 255) << 16 ^ Si[this.C2 >> 24 & 255] << 24) ^ var1[var2][1];
         var5 = inv_mcol(Si[this.C2 & 255] & 255 ^ (Si[this.C1 >> 8 & 255] & 255) << 8 ^ (Si[this.C0 >> 16 & 255] & 255) << 16 ^ Si[this.C3 >> 24 & 255] << 24) ^ var1[var2][2];
         var6 = inv_mcol(Si[this.C3 & 255] & 255 ^ (Si[this.C2 >> 8 & 255] & 255) << 8 ^ (Si[this.C1 >> 16 & 255] & 255) << 16 ^ Si[this.C0 >> 24 & 255] << 24) ^ var1[var2--][3];
         this.C0 = inv_mcol(Si[var3 & 255] & 255 ^ (Si[var6 >> 8 & 255] & 255) << 8 ^ (Si[var5 >> 16 & 255] & 255) << 16 ^ Si[var4 >> 24 & 255] << 24) ^ var1[var2][0];
         this.C1 = inv_mcol(Si[var4 & 255] & 255 ^ (Si[var3 >> 8 & 255] & 255) << 8 ^ (Si[var6 >> 16 & 255] & 255) << 16 ^ Si[var5 >> 24 & 255] << 24) ^ var1[var2][1];
         this.C2 = inv_mcol(Si[var5 & 255] & 255 ^ (Si[var4 >> 8 & 255] & 255) << 8 ^ (Si[var3 >> 16 & 255] & 255) << 16 ^ Si[var6 >> 24 & 255] << 24) ^ var1[var2][2];
      }

      var3 = inv_mcol(Si[this.C0 & 255] & 255 ^ (Si[this.C3 >> 8 & 255] & 255) << 8 ^ (Si[this.C2 >> 16 & 255] & 255) << 16 ^ Si[this.C1 >> 24 & 255] << 24) ^ var1[var2][0];
      var4 = inv_mcol(Si[this.C1 & 255] & 255 ^ (Si[this.C0 >> 8 & 255] & 255) << 8 ^ (Si[this.C3 >> 16 & 255] & 255) << 16 ^ Si[this.C2 >> 24 & 255] << 24) ^ var1[var2][1];
      var5 = inv_mcol(Si[this.C2 & 255] & 255 ^ (Si[this.C1 >> 8 & 255] & 255) << 8 ^ (Si[this.C0 >> 16 & 255] & 255) << 16 ^ Si[this.C3 >> 24 & 255] << 24) ^ var1[var2][2];
      var6 = inv_mcol(Si[this.C3 & 255] & 255 ^ (Si[this.C2 >> 8 & 255] & 255) << 8 ^ (Si[this.C1 >> 16 & 255] & 255) << 16 ^ Si[this.C0 >> 24 & 255] << 24) ^ var1[var2][3];
      this.C0 = Si[var3 & 255] & 255 ^ (Si[var6 >> 8 & 255] & 255) << 8 ^ (Si[var5 >> 16 & 255] & 255) << 16 ^ Si[var4 >> 24 & 255] << 24 ^ var1[0][0];
      this.C1 = Si[var4 & 255] & 255 ^ (Si[var3 >> 8 & 255] & 255) << 8 ^ (Si[var6 >> 16 & 255] & 255) << 16 ^ Si[var5 >> 24 & 255] << 24 ^ var1[0][1];
      this.C2 = Si[var5 & 255] & 255 ^ (Si[var4 >> 8 & 255] & 255) << 8 ^ (Si[var3 >> 16 & 255] & 255) << 16 ^ Si[var6 >> 24 & 255] << 24 ^ var1[0][2];
      this.C3 = Si[var6 & 255] & 255 ^ (Si[var5 >> 8 & 255] & 255) << 8 ^ (Si[var4 >> 16 & 255] & 255) << 16 ^ Si[var3 >> 24 & 255] << 24 ^ var1[0][3];
   }
}
