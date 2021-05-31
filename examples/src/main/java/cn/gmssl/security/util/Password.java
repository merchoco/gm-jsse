package cn.gmssl.security.util;

import java.io.ByteArrayInputStream;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.util.Arrays;
import sun.misc.SharedSecrets;

public class Password {
   private static volatile CharsetEncoder enc;

   public static char[] readPassword(InputStream var0) throws IOException {
      return readPassword(var0, false);
   }

   public static char[] readPassword(InputStream var0, boolean var1) throws IOException {
      char[] var2 = null;
      byte[] var3 = null;

      try {
         Console var4 = null;
         if (!var1 && var0 == System.in && (var4 = System.console()) != null) {
            var2 = var4.readPassword();
            if (var2 != null && var2.length == 0) {
               return null;
            }

            var3 = convertToBytes(var2);
            var0 = new ByteArrayInputStream(var3);
         }

         char[] var5;
         char[] var6 = var5 = new char[128];
         int var8 = var6.length;
         int var9 = 0;
         boolean var11 = false;

         while(!var11) {
            int var10;
            switch(var10 = ((InputStream)var0).read()) {
            case -1:
            case 10:
               var11 = true;
               continue;
            case 13:
               int var12 = ((InputStream)var0).read();
               if (var12 == 10 || var12 == -1) {
                  var11 = true;
                  continue;
               }

               if (!(var0 instanceof PushbackInputStream)) {
                  var0 = new PushbackInputStream((InputStream)var0);
               }

               ((PushbackInputStream)var0).unread(var12);
            }

            --var8;
            if (var8 < 0) {
               var6 = new char[var9 + 128];
               var8 = var6.length - var9 - 1;
               System.arraycopy(var5, 0, var6, 0, var9);
               Arrays.fill(var5, ' ');
               var5 = var6;
            }

            var6[var9++] = (char)var10;
         }

         if (var9 != 0) {
            char[] var17 = new char[var9];
            System.arraycopy(var6, 0, var17, 0, var9);
            Arrays.fill(var6, ' ');
            char[] var14 = var17;
            return var14;
         } else {
            return null;
         }
      } finally {
         if (var2 != null) {
            Arrays.fill(var2, ' ');
         }

         if (var3 != null) {
            Arrays.fill(var3, (byte)0);
         }

      }
   }

   private static byte[] convertToBytes(char[] var0) {
      if (enc == null) {
         Class var1 = Password.class;
         synchronized(Password.class) {
            enc = SharedSecrets.getJavaIOAccess().charset().newEncoder().onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE);
         }
      }

      byte[] var6 = new byte[(int)(enc.maxBytesPerChar() * (float)var0.length)];
      ByteBuffer var2 = ByteBuffer.wrap(var6);
      CharsetEncoder var3 = enc;
      synchronized(enc) {
         enc.reset().encode(CharBuffer.wrap(var0), var2, true);
      }

      if (var2.position() < var6.length) {
         var6[var2.position()] = 10;
      }

      return var6;
   }
}
