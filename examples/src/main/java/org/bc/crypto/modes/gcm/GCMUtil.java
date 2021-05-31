package org.bc.crypto.modes.gcm;

import org.bc.crypto.util.Pack;
import org.bc.util.Arrays;

abstract class GCMUtil {
   static byte[] oneAsBytes() {
      byte[] var0 = new byte[16];
      var0[0] = -128;
      return var0;
   }

   static int[] oneAsInts() {
      int[] var0 = new int[4];
      var0[0] = Integer.MIN_VALUE;
      return var0;
   }

   static byte[] asBytes(int[] var0) {
      byte[] var1 = new byte[16];
      Pack.intToBigEndian(var0, var1, 0);
      return var1;
   }

   static int[] asInts(byte[] var0) {
      int[] var1 = new int[4];
      Pack.bigEndianToInt(var0, 0, var1);
      return var1;
   }

   static void asInts(byte[] var0, int[] var1) {
      Pack.bigEndianToInt(var0, 0, var1);
   }

   static void multiply(byte[] var0, byte[] var1) {
      byte[] var2 = Arrays.clone(var0);
      byte[] var3 = new byte[16];

      for(int var4 = 0; var4 < 16; ++var4) {
         byte var5 = var1[var4];

         for(int var6 = 7; var6 >= 0; --var6) {
            if ((var5 & 1 << var6) != 0) {
               xor(var3, var2);
            }

            boolean var7 = (var2[15] & 1) != 0;
            shiftRight(var2);
            if (var7) {
               var2[0] ^= -31;
            }
         }
      }

      System.arraycopy(var3, 0, var0, 0, 16);
   }

   static void multiplyP(int[] var0) {
      boolean var1 = (var0[3] & 1) != 0;
      shiftRight(var0);
      if (var1) {
         var0[0] ^= -520093696;
      }

   }

   static void multiplyP(int[] var0, int[] var1) {
      boolean var2 = (var0[3] & 1) != 0;
      shiftRight(var0, var1);
      if (var2) {
         var1[0] ^= -520093696;
      }

   }

   static void multiplyP8(int[] var0) {
      int var1 = var0[3];
      shiftRightN(var0, 8);

      for(int var2 = 7; var2 >= 0; --var2) {
         if ((var1 & 1 << var2) != 0) {
            var0[0] ^= -520093696 >>> 7 - var2;
         }
      }

   }

   static void multiplyP8(int[] var0, int[] var1) {
      int var2 = var0[3];
      shiftRightN(var0, 8, var1);

      for(int var3 = 7; var3 >= 0; --var3) {
         if ((var2 & 1 << var3) != 0) {
            var1[0] ^= -520093696 >>> 7 - var3;
         }
      }

   }

   static void shiftRight(byte[] var0) {
      int var1 = 0;
      int var2 = 0;

      while(true) {
         int var3 = var0[var1] & 255;
         var0[var1] = (byte)(var3 >>> 1 | var2);
         ++var1;
         if (var1 == 16) {
            return;
         }

         var2 = (var3 & 1) << 7;
      }
   }

   static void shiftRight(byte[] var0, byte[] var1) {
      int var2 = 0;
      int var3 = 0;

      while(true) {
         int var4 = var0[var2] & 255;
         var1[var2] = (byte)(var4 >>> 1 | var3);
         ++var2;
         if (var2 == 16) {
            return;
         }

         var3 = (var4 & 1) << 7;
      }
   }

   static void shiftRight(int[] var0) {
      int var1 = 0;
      int var2 = 0;

      while(true) {
         int var3 = var0[var1];
         var0[var1] = var3 >>> 1 | var2;
         ++var1;
         if (var1 == 4) {
            return;
         }

         var2 = var3 << 31;
      }
   }

   static void shiftRight(int[] var0, int[] var1) {
      int var2 = 0;
      int var3 = 0;

      while(true) {
         int var4 = var0[var2];
         var1[var2] = var4 >>> 1 | var3;
         ++var2;
         if (var2 == 4) {
            return;
         }

         var3 = var4 << 31;
      }
   }

   static void shiftRightN(int[] var0, int var1) {
      int var2 = 0;
      int var3 = 0;

      while(true) {
         int var4 = var0[var2];
         var0[var2] = var4 >>> var1 | var3;
         ++var2;
         if (var2 == 4) {
            return;
         }

         var3 = var4 << 32 - var1;
      }
   }

   static void shiftRightN(int[] var0, int var1, int[] var2) {
      int var3 = 0;
      int var4 = 0;

      while(true) {
         int var5 = var0[var3];
         var2[var3] = var5 >>> var1 | var4;
         ++var3;
         if (var3 == 4) {
            return;
         }

         var4 = var5 << 32 - var1;
      }
   }

   static void xor(byte[] var0, byte[] var1) {
      for(int var2 = 15; var2 >= 0; --var2) {
         var0[var2] ^= var1[var2];
      }

   }

   static void xor(byte[] var0, byte[] var1, int var2, int var3) {
      while(var3-- > 0) {
         var0[var3] ^= var1[var2 + var3];
      }

   }

   static void xor(byte[] var0, byte[] var1, byte[] var2) {
      for(int var3 = 15; var3 >= 0; --var3) {
         var2[var3] = (byte)(var0[var3] ^ var1[var3]);
      }

   }

   static void xor(int[] var0, int[] var1) {
      for(int var2 = 3; var2 >= 0; --var2) {
         var0[var2] ^= var1[var2];
      }

   }

   static void xor(int[] var0, int[] var1, int[] var2) {
      for(int var3 = 3; var3 >= 0; --var3) {
         var2[var3] = var0[var3] ^ var1[var3];
      }

   }
}
