package org.bc.util;

import java.math.BigInteger;

public final class Arrays {
   public static boolean areEqual(boolean[] var0, boolean[] var1) {
      if (var0 == var1) {
         return true;
      } else if (var0 != null && var1 != null) {
         if (var0.length != var1.length) {
            return false;
         } else {
            for(int var2 = 0; var2 != var0.length; ++var2) {
               if (var0[var2] != var1[var2]) {
                  return false;
               }
            }

            return true;
         }
      } else {
         return false;
      }
   }

   public static boolean areEqual(char[] var0, char[] var1) {
      if (var0 == var1) {
         return true;
      } else if (var0 != null && var1 != null) {
         if (var0.length != var1.length) {
            return false;
         } else {
            for(int var2 = 0; var2 != var0.length; ++var2) {
               if (var0[var2] != var1[var2]) {
                  return false;
               }
            }

            return true;
         }
      } else {
         return false;
      }
   }

   public static boolean areEqual(byte[] var0, byte[] var1) {
      if (var0 == var1) {
         return true;
      } else if (var0 != null && var1 != null) {
         if (var0.length != var1.length) {
            return false;
         } else {
            for(int var2 = 0; var2 != var0.length; ++var2) {
               if (var0[var2] != var1[var2]) {
                  return false;
               }
            }

            return true;
         }
      } else {
         return false;
      }
   }

   public static boolean constantTimeAreEqual(byte[] var0, byte[] var1) {
      if (var0 == var1) {
         return true;
      } else if (var0 != null && var1 != null) {
         if (var0.length != var1.length) {
            return false;
         } else {
            int var2 = 0;

            for(int var3 = 0; var3 != var0.length; ++var3) {
               var2 |= var0[var3] ^ var1[var3];
            }

            return var2 == 0;
         }
      } else {
         return false;
      }
   }

   public static boolean areEqual(int[] var0, int[] var1) {
      if (var0 == var1) {
         return true;
      } else if (var0 != null && var1 != null) {
         if (var0.length != var1.length) {
            return false;
         } else {
            for(int var2 = 0; var2 != var0.length; ++var2) {
               if (var0[var2] != var1[var2]) {
                  return false;
               }
            }

            return true;
         }
      } else {
         return false;
      }
   }

   public static boolean areEqual(long[] var0, long[] var1) {
      if (var0 == var1) {
         return true;
      } else if (var0 != null && var1 != null) {
         if (var0.length != var1.length) {
            return false;
         } else {
            for(int var2 = 0; var2 != var0.length; ++var2) {
               if (var0[var2] != var1[var2]) {
                  return false;
               }
            }

            return true;
         }
      } else {
         return false;
      }
   }

   public static boolean areEqual(BigInteger[] var0, BigInteger[] var1) {
      if (var0 == var1) {
         return true;
      } else if (var0 != null && var1 != null) {
         if (var0.length != var1.length) {
            return false;
         } else {
            for(int var2 = 0; var2 != var0.length; ++var2) {
               if (!var0[var2].equals(var1[var2])) {
                  return false;
               }
            }

            return true;
         }
      } else {
         return false;
      }
   }

   public static void fill(byte[] var0, byte var1) {
      for(int var2 = 0; var2 < var0.length; ++var2) {
         var0[var2] = var1;
      }

   }

   public static void fill(char[] var0, char var1) {
      for(int var2 = 0; var2 < var0.length; ++var2) {
         var0[var2] = var1;
      }

   }

   public static void fill(long[] var0, long var1) {
      for(int var3 = 0; var3 < var0.length; ++var3) {
         var0[var3] = var1;
      }

   }

   public static void fill(short[] var0, short var1) {
      for(int var2 = 0; var2 < var0.length; ++var2) {
         var0[var2] = var1;
      }

   }

   public static void fill(int[] var0, int var1) {
      for(int var2 = 0; var2 < var0.length; ++var2) {
         var0[var2] = var1;
      }

   }

   public static int hashCode(byte[] var0) {
      if (var0 == null) {
         return 0;
      } else {
         int var1 = var0.length;
         int var2 = var1 + 1;

         while(true) {
            --var1;
            if (var1 < 0) {
               return var2;
            }

            var2 *= 257;
            var2 ^= var0[var1];
         }
      }
   }

   public static int hashCode(char[] var0) {
      if (var0 == null) {
         return 0;
      } else {
         int var1 = var0.length;
         int var2 = var1 + 1;

         while(true) {
            --var1;
            if (var1 < 0) {
               return var2;
            }

            var2 *= 257;
            var2 ^= var0[var1];
         }
      }
   }

   public static int hashCode(int[][] var0) {
      int var1 = 0;

      for(int var2 = 0; var2 != var0.length; ++var2) {
         var1 = var1 * 257 + hashCode(var0[var2]);
      }

      return var1;
   }

   public static int hashCode(int[] var0) {
      if (var0 == null) {
         return 0;
      } else {
         int var1 = var0.length;
         int var2 = var1 + 1;

         while(true) {
            --var1;
            if (var1 < 0) {
               return var2;
            }

            var2 *= 257;
            var2 ^= var0[var1];
         }
      }
   }

   public static int hashCode(short[][][] var0) {
      int var1 = 0;

      for(int var2 = 0; var2 != var0.length; ++var2) {
         var1 = var1 * 257 + hashCode(var0[var2]);
      }

      return var1;
   }

   public static int hashCode(short[][] var0) {
      int var1 = 0;

      for(int var2 = 0; var2 != var0.length; ++var2) {
         var1 = var1 * 257 + hashCode(var0[var2]);
      }

      return var1;
   }

   public static int hashCode(short[] var0) {
      if (var0 == null) {
         return 0;
      } else {
         int var1 = var0.length;
         int var2 = var1 + 1;

         while(true) {
            --var1;
            if (var1 < 0) {
               return var2;
            }

            var2 *= 257;
            var2 ^= var0[var1] & 255;
         }
      }
   }

   public static int hashCode(BigInteger[] var0) {
      if (var0 == null) {
         return 0;
      } else {
         int var1 = var0.length;
         int var2 = var1 + 1;

         while(true) {
            --var1;
            if (var1 < 0) {
               return var2;
            }

            var2 *= 257;
            var2 ^= var0[var1].hashCode();
         }
      }
   }

   public static byte[] clone(byte[] var0) {
      if (var0 == null) {
         return null;
      } else {
         byte[] var1 = new byte[var0.length];
         System.arraycopy(var0, 0, var1, 0, var0.length);
         return var1;
      }
   }

   public static int[] clone(int[] var0) {
      if (var0 == null) {
         return null;
      } else {
         int[] var1 = new int[var0.length];
         System.arraycopy(var0, 0, var1, 0, var0.length);
         return var1;
      }
   }

   public static short[] clone(short[] var0) {
      if (var0 == null) {
         return null;
      } else {
         short[] var1 = new short[var0.length];
         System.arraycopy(var0, 0, var1, 0, var0.length);
         return var1;
      }
   }

   public static BigInteger[] clone(BigInteger[] var0) {
      if (var0 == null) {
         return null;
      } else {
         BigInteger[] var1 = new BigInteger[var0.length];
         System.arraycopy(var0, 0, var1, 0, var0.length);
         return var1;
      }
   }

   public static byte[] copyOf(byte[] var0, int var1) {
      byte[] var2 = new byte[var1];
      if (var1 < var0.length) {
         System.arraycopy(var0, 0, var2, 0, var1);
      } else {
         System.arraycopy(var0, 0, var2, 0, var0.length);
      }

      return var2;
   }

   public static char[] copyOf(char[] var0, int var1) {
      char[] var2 = new char[var1];
      if (var1 < var0.length) {
         System.arraycopy(var0, 0, var2, 0, var1);
      } else {
         System.arraycopy(var0, 0, var2, 0, var0.length);
      }

      return var2;
   }

   public static int[] copyOf(int[] var0, int var1) {
      int[] var2 = new int[var1];
      if (var1 < var0.length) {
         System.arraycopy(var0, 0, var2, 0, var1);
      } else {
         System.arraycopy(var0, 0, var2, 0, var0.length);
      }

      return var2;
   }

   public static long[] copyOf(long[] var0, int var1) {
      long[] var2 = new long[var1];
      if (var1 < var0.length) {
         System.arraycopy(var0, 0, var2, 0, var1);
      } else {
         System.arraycopy(var0, 0, var2, 0, var0.length);
      }

      return var2;
   }

   public static BigInteger[] copyOf(BigInteger[] var0, int var1) {
      BigInteger[] var2 = new BigInteger[var1];
      if (var1 < var0.length) {
         System.arraycopy(var0, 0, var2, 0, var1);
      } else {
         System.arraycopy(var0, 0, var2, 0, var0.length);
      }

      return var2;
   }

   public static byte[] copyOfRange(byte[] var0, int var1, int var2) {
      int var3 = getLength(var1, var2);
      byte[] var4 = new byte[var3];
      if (var0.length - var1 < var3) {
         System.arraycopy(var0, var1, var4, 0, var0.length - var1);
      } else {
         System.arraycopy(var0, var1, var4, 0, var3);
      }

      return var4;
   }

   public static int[] copyOfRange(int[] var0, int var1, int var2) {
      int var3 = getLength(var1, var2);
      int[] var4 = new int[var3];
      if (var0.length - var1 < var3) {
         System.arraycopy(var0, var1, var4, 0, var0.length - var1);
      } else {
         System.arraycopy(var0, var1, var4, 0, var3);
      }

      return var4;
   }

   public static long[] copyOfRange(long[] var0, int var1, int var2) {
      int var3 = getLength(var1, var2);
      long[] var4 = new long[var3];
      if (var0.length - var1 < var3) {
         System.arraycopy(var0, var1, var4, 0, var0.length - var1);
      } else {
         System.arraycopy(var0, var1, var4, 0, var3);
      }

      return var4;
   }

   public static BigInteger[] copyOfRange(BigInteger[] var0, int var1, int var2) {
      int var3 = getLength(var1, var2);
      BigInteger[] var4 = new BigInteger[var3];
      if (var0.length - var1 < var3) {
         System.arraycopy(var0, var1, var4, 0, var0.length - var1);
      } else {
         System.arraycopy(var0, var1, var4, 0, var3);
      }

      return var4;
   }

   private static int getLength(int var0, int var1) {
      int var2 = var1 - var0;
      if (var2 < 0) {
         StringBuffer var3 = new StringBuffer(var0);
         var3.append(" > ").append(var1);
         throw new IllegalArgumentException(var3.toString());
      } else {
         return var2;
      }
   }
}
