package org.bc.math.ntru.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import org.bc.util.Arrays;

public class ArrayEncoder {
   private static final int[] COEFF1_TABLE = new int[]{0, 0, 0, 1, 1, 1, -1, -1};
   private static final int[] COEFF2_TABLE = new int[]{0, 1, -1, 0, 1, -1, 0, 1};
   private static final int[] BIT1_TABLE = new int[]{1, 1, 1, 0, 0, 0, 1, 0, 1};
   private static final int[] BIT2_TABLE = new int[]{1, 1, 1, 1, 0, 0, 0, 1, 0};
   private static final int[] BIT3_TABLE = new int[]{1, 0, 1, 0, 0, 1, 1, 1, 0};

   public static byte[] encodeModQ(int[] var0, int var1) {
      int var2 = 31 - Integer.numberOfLeadingZeros(var1);
      int var3 = var0.length * var2;
      int var4 = (var3 + 7) / 8;
      byte[] var5 = new byte[var4];
      int var6 = 0;
      int var7 = 0;

      for(int var8 = 0; var8 < var0.length; ++var8) {
         for(int var9 = 0; var9 < var2; ++var9) {
            int var10 = var0[var8] >> var9 & 1;
            var5[var7] = (byte)(var5[var7] | var10 << var6);
            if (var6 == 7) {
               var6 = 0;
               ++var7;
            } else {
               ++var6;
            }
         }
      }

      return var5;
   }

   public static int[] decodeModQ(byte[] var0, int var1, int var2) {
      int[] var3 = new int[var1];
      int var4 = 31 - Integer.numberOfLeadingZeros(var2);
      int var5 = var1 * var4;
      int var6 = 0;

      for(int var7 = 0; var7 < var5; ++var7) {
         if (var7 > 0 && var7 % var4 == 0) {
            ++var6;
         }

         int var8 = getBit(var0, var7);
         var3[var6] += var8 << var7 % var4;
      }

      return var3;
   }

   public static int[] decodeModQ(InputStream var0, int var1, int var2) throws IOException {
      int var3 = 31 - Integer.numberOfLeadingZeros(var2);
      int var4 = (var1 * var3 + 7) / 8;
      byte[] var5 = Util.readFullLength(var0, var4);
      return decodeModQ(var5, var1, var2);
   }

   public static int[] decodeMod3Sves(byte[] var0, int var1) {
      int[] var2 = new int[var1];
      int var3 = 0;
      int var4 = 0;

      while(var4 < var0.length * 8) {
         int var5 = getBit(var0, var4++);
         int var6 = getBit(var0, var4++);
         int var7 = getBit(var0, var4++);
         int var8 = var5 * 4 + var6 * 2 + var7;
         var2[var3++] = COEFF1_TABLE[var8];
         var2[var3++] = COEFF2_TABLE[var8];
         if (var3 > var1 - 2) {
            break;
         }
      }

      return var2;
   }

   public static byte[] encodeMod3Sves(int[] var0) {
      int var1 = (var0.length * 3 + 1) / 2;
      int var2 = (var1 + 7) / 8;
      byte[] var3 = new byte[var2];
      int var4 = 0;
      int var5 = 0;
      int var6 = 0;

      while(var6 < var0.length / 2 * 2) {
         int var7 = var0[var6++] + 1;
         int var8 = var0[var6++] + 1;
         if (var7 == 0 && var8 == 0) {
            throw new IllegalStateException("Illegal encoding!");
         }

         int var9 = var7 * 3 + var8;
         int[] var10 = new int[]{BIT1_TABLE[var9], BIT2_TABLE[var9], BIT3_TABLE[var9]};

         for(int var11 = 0; var11 < 3; ++var11) {
            var3[var5] = (byte)(var3[var5] | var10[var11] << var4);
            if (var4 == 7) {
               var4 = 0;
               ++var5;
            } else {
               ++var4;
            }
         }
      }

      return var3;
   }

   public static byte[] encodeMod3Tight(int[] var0) {
      BigInteger var1 = BigInteger.ZERO;

      int var2;
      for(var2 = var0.length - 1; var2 >= 0; --var2) {
         var1 = var1.multiply(BigInteger.valueOf(3L));
         var1 = var1.add(BigInteger.valueOf((long)(var0[var2] + 1)));
      }

      var2 = (BigInteger.valueOf(3L).pow(var0.length).bitLength() + 7) / 8;
      byte[] var3 = var1.toByteArray();
      if (var3.length < var2) {
         byte[] var4 = new byte[var2];
         System.arraycopy(var3, 0, var4, var2 - var3.length, var3.length);
         return var4;
      } else {
         if (var3.length > var2) {
            var3 = Arrays.copyOfRange((byte[])var3, 1, var3.length);
         }

         return var3;
      }
   }

   public static int[] decodeMod3Tight(byte[] var0, int var1) {
      BigInteger var2 = new BigInteger(1, var0);
      int[] var3 = new int[var1];

      for(int var4 = 0; var4 < var1; ++var4) {
         var3[var4] = var2.mod(BigInteger.valueOf(3L)).intValue() - 1;
         if (var3[var4] > 1) {
            var3[var4] -= 3;
         }

         var2 = var2.divide(BigInteger.valueOf(3L));
      }

      return var3;
   }

   public static int[] decodeMod3Tight(InputStream var0, int var1) throws IOException {
      int var2 = (int)Math.ceil((double)var1 * Math.log(3.0D) / Math.log(2.0D) / 8.0D);
      byte[] var3 = Util.readFullLength(var0, var2);
      return decodeMod3Tight(var3, var1);
   }

   private static int getBit(byte[] var0, int var1) {
      int var2 = var1 / 8;
      int var3 = var0[var2] & 255;
      return var3 >> var1 % 8 & 1;
   }
}
