package cn.gmssl.crypto.util;

public class ByteUtil {
   public static byte[] merge(byte[] var0, byte[] var1) {
      int var2 = var0.length + var1.length;
      byte[] var3 = new byte[var2];
      System.arraycopy(var0, 0, var3, 0, var0.length);
      System.arraycopy(var1, 0, var3, var1.length, var2);
      return var3;
   }

   public static int bigEndianToInt(byte var0, byte var1, byte var2, byte var3) {
      int var4 = var0 << 24 & -16777216 | var1 << 16 & 16711680 | var2 << 8 & '\uff00' | var3 & 255;
      return var4;
   }

   public static int bigEndianToInt(byte[] var0, int var1) {
      byte var2 = var0[var1];
      ++var1;
      byte var3 = var0[var1];
      ++var1;
      byte var4 = var0[var1];
      ++var1;
      byte var5 = var0[var1];
      return bigEndianToInt(var2, var3, var4, var5);
   }

   public static void intToBigEndian(int var0, byte[] var1, int var2) {
      var1[var2] = (byte)(var0 >>> 24);
      ++var2;
      var1[var2] = (byte)(var0 >>> 16);
      ++var2;
      var1[var2] = (byte)(var0 >>> 8);
      ++var2;
      var1[var2] = (byte)var0;
   }

   public static int toUnsignedInt(byte var0) {
      int var1 = var0 >= 0 ? var0 : 256 + var0;
      return var1;
   }

   public static String hexEncode(byte[] var0, int var1, int var2) {
      StringBuffer var3 = new StringBuffer();

      for(int var4 = 0; var4 < var2; ++var4) {
         int var5 = var0[var1 + var4] & 255;
         if (var5 < 16) {
            var3.append("0");
            var3.append(Integer.toString(var5, 16));
         } else {
            var3.append(Integer.toString(var5, 16));
         }
      }

      return var3.toString();
   }

   public static byte[] hexDecode(String var0) {
      int var1 = var0.length();
      if (var1 % 2 != 0) {
         var0 = "0" + var0;
         ++var1;
      }

      byte[] var2 = new byte[var1 / 2];

      for(int var3 = 0; var3 < var2.length; ++var3) {
         String var4 = var0.substring(var3 * 2, var3 * 2 + 2);
         var2[var3] = (byte)Integer.parseInt(var4, 16);
      }

      return var2;
   }

   public static String hexEncode(byte[] var0) {
      return hexEncode(var0, 0, var0.length);
   }

   public static byte[] replace(byte[] var0, byte[] var1, byte[] var2) {
      int var3 = indexOf(var0, 0, var0.length, var1, 0, var1.length);
      if (var3 != -1) {
         byte[] var4 = new byte[var0.length - var1.length + var2.length];
         System.arraycopy(var0, 0, var4, 0, var3);
         System.arraycopy(var2, 0, var4, var3, var2.length);
         System.arraycopy(var0, var3 + var1.length, var4, var3 + var2.length, var0.length - var3 - var1.length);
         return var4;
      } else {
         return var0;
      }
   }

   public static int indexOf(byte[] var0, int var1, int var2, byte[] var3, int var4, int var5) {
      byte var6 = 0;
      if (var6 >= var2) {
         return var5 == 0 ? var2 : -1;
      } else {
         if (var6 < 0) {
            var6 = 0;
         }

         if (var5 == 0) {
            return var6;
         } else {
            byte var7 = var3[var4];
            int var8 = var1 + var6;
            int var9 = var1 + (var2 - var5);

            while(true) {
               while(var8 > var9 || byteEqualsIgnoreCase(var0[var8], var7)) {
                  if (var8 > var9) {
                     return -1;
                  }

                  int var10 = var8 + 1;
                  int var11 = var10 + var5 - 1;
                  int var12 = var4 + 1;

                  do {
                     if (var10 >= var11) {
                        return var8 - var1;
                     }
                  } while(byteEqualsIgnoreCase(var0[var10++], var3[var12++]));

                  ++var8;
               }

               ++var8;
            }
         }
      }
   }

   private static boolean byteEqualsIgnoreCase(byte var0, byte var1) {
      if (var0 == var1) {
         return true;
      } else {
         return var0 == (byte)(var1 - 32);
      }
   }

   public static byte[] padding(byte[] var0, int var1) {
      int var2 = var1 - var0.length % var1;
      byte[] var3 = new byte[var0.length + var2];
      System.arraycopy(var0, 0, var3, 0, var0.length);

      for(int var4 = 0; var4 < var2; ++var4) {
         var3[var0.length + var4] = (byte)(var2 & 255);
      }

      return var3;
   }

   public static byte[] unpadding(byte[] var0) {
      byte var1 = var0[var0.length - 1];
      byte[] var2 = new byte[var0.length - var1];
      System.arraycopy(var0, 0, var2, 0, var2.length);
      return var2;
   }
}
