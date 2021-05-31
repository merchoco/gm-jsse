package cn.gmssl.security.util;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.StringTokenizer;

public class PathList {
   public static String appendPath(String var0, String var1) {
      if (var0 != null && var0.length() != 0) {
         return var1 != null && var1.length() != 0 ? var0 + File.pathSeparator + var1 : var0;
      } else {
         return var1;
      }
   }

   public static URL[] pathToURLs(String var0) {
      StringTokenizer var1 = new StringTokenizer(var0, File.pathSeparator);
      URL[] var2 = new URL[var1.countTokens()];
      int var3 = 0;

      while(var1.hasMoreTokens()) {
         URL var4 = fileToURL(new File(var1.nextToken()));
         if (var4 != null) {
            var2[var3++] = var4;
         }
      }

      if (var2.length != var3) {
         URL[] var5 = new URL[var3];
         System.arraycopy(var2, 0, var5, 0, var3);
         var2 = var5;
      }

      return var2;
   }

   private static URL fileToURL(File var0) {
      String var1;
      try {
         var1 = var0.getCanonicalPath();
      } catch (IOException var4) {
         var1 = var0.getAbsolutePath();
      }

      var1 = var1.replace(File.separatorChar, '/');
      if (!var1.startsWith("/")) {
         var1 = "/" + var1;
      }

      if (!var0.isFile()) {
         var1 = var1 + "/";
      }

      try {
         return new URL("file", "", var1);
      } catch (MalformedURLException var3) {
         throw new IllegalArgumentException("file");
      }
   }
}
