package cn.gmssl.crypto.util;

import java.math.BigInteger;
import org.bc.util.encoders.Hex;

public class PrintUtil {
   public static void printHex(int[] var0, int var1, int var2, String var3) {
      if (var1 + var2 > var0.length) {
         throw new RuntimeException("���ӡ����ϢԽ��");
      } else {
         System.out.println(var3);
         int var4 = 0;

         for(int var5 = var1; var5 < var1 + var2; ++var5) {
            String var6 = Integer.toHexString(var0[var5]);
            var6 = padString(var6);
            System.out.print(var6 + " ");
            ++var4;
            if (var4 % 8 == 0) {
               System.out.println();
            }
         }

         System.out.println();
      }
   }

   public static void printHex(int[] var0, String var1) {
      printHex((int[])var0, 0, var0.length, var1);
   }

   public static void printHex(byte[] var0, int var1, int var2, String var3) {
      if (Debug.DEBUG) {
         if (var1 + var2 > var0.length) {
            throw new RuntimeException("���ӡ����ϢԽ��");
         } else {
            System.out.println(var3);
            String var4 = new String(Hex.encode(var0, var1, var2));
            StringBuffer var5 = new StringBuffer(padString(var4));
            int var6 = 0;
            int var7 = 0;

            for(int var8 = 0; var6 < var4.length(); ++var6) {
               if (var6 != 0) {
                  if (var6 % 64 == 0) {
                     var5.insert(var6 + var7 + var8++, '\n');
                  } else if (var6 % 8 == 0) {
                     var5.insert(var6 + var7++ + var8, ' ');
                  }
               }
            }

            System.out.println(var5.toString());
         }
      }
   }

   public static void printHex(byte[] var0, String var1) {
      printHex((byte[])var0, 0, var0.length, var1);
   }

   public static void printHex(BigInteger var0, String var1) {
      if (Debug.DEBUG) {
         if (var0 != null) {
            System.out.println(var1);
            System.out.println(var0.toString(16));
         }

      }
   }

   public static String padString(String var0) {
      boolean var1 = var0.length() % 2 != 0;
      if (var1) {
         var0 = "0" + var0;
      }

      return var0;
   }
}
