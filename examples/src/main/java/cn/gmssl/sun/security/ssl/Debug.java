package cn.gmssl.sun.security.ssl;

import java.io.PrintStream;
import java.security.AccessController;
import java.util.Locale;
import sun.security.action.GetPropertyAction;

public class Debug {
   private String prefix;
   private static String args = (String)AccessController.doPrivileged(new GetPropertyAction("javax.net.debug", ""));

   static {
      args = args.toLowerCase(Locale.ENGLISH);
      if (args.equals("help")) {
         Help();
      }

   }

   public static void Help() {
      System.err.println();
      System.err.println("all            turn on all debugging");
      System.err.println("ssl            turn on ssl debugging");
      System.err.println();
      System.err.println("The following can be used with ssl:");
      System.err.println("\trecord       enable per-record tracing");
      System.err.println("\thandshake    print each handshake message");
      System.err.println("\tkeygen       print key generation data");
      System.err.println("\tsession      print session activity");
      System.err.println("\tdefaultctx   print default SSL initialization");
      System.err.println("\tsslctx       print SSLContext tracing");
      System.err.println("\tsessioncache print session cache tracing");
      System.err.println("\tkeymanager   print key manager tracing");
      System.err.println("\ttrustmanager print trust manager tracing");
      System.err.println("\tpluggability print pluggability tracing");
      System.err.println();
      System.err.println("\thandshake debugging can be widened with:");
      System.err.println("\tdata         hex dump of each handshake message");
      System.err.println("\tverbose      verbose handshake message printing");
      System.err.println();
      System.err.println("\trecord debugging can be widened with:");
      System.err.println("\tplaintext    hex dump of record plaintext");
      System.err.println("\tpacket       print raw SSL/TLS packets");
      System.err.println();
      System.exit(0);
   }

   public static Debug getInstance(String var0) {
      return getInstance(var0, var0);
   }

   public static Debug getInstance(String var0, String var1) {
      if (isOn(var0)) {
         Debug var2 = new Debug();
         var2.prefix = var1;
         return var2;
      } else {
         return null;
      }
   }

   public static boolean isOn(String var0) {
      if (args == null) {
         return false;
      } else {
         boolean var1 = false;
         var0 = var0.toLowerCase(Locale.ENGLISH);
         if (args.indexOf("all") != -1) {
            return true;
         } else {
            int var2;
            if ((var2 = args.indexOf("ssl")) != -1 && args.indexOf("sslctx", var2) == -1 && !var0.equals("data") && !var0.equals("packet") && !var0.equals("plaintext")) {
               return true;
            } else {
               return args.indexOf(var0) != -1;
            }
         }
      }
   }

   public void println(String var1) {
      System.err.println(this.prefix + ": " + var1);
   }

   public void println() {
      System.err.println(this.prefix + ":");
   }

   public static void println(String var0, String var1) {
      System.err.println(var0 + ": " + var1);
   }

   public static void println(PrintStream var0, String var1, byte[] var2) {
      var0.print(var1 + ":  { ");
      if (var2 == null) {
         var0.print("null");
      } else {
         for(int var3 = 0; var3 < var2.length; ++var3) {
            if (var3 != 0) {
               var0.print(", ");
            }

            var0.print(var2[var3] & 255);
         }
      }

      var0.println(" }");
   }

   static boolean getBooleanProperty(String var0, boolean var1) {
      String var2 = (String)AccessController.doPrivileged(new GetPropertyAction(var0));
      if (var2 == null) {
         return var1;
      } else if (var2.equalsIgnoreCase("false")) {
         return false;
      } else if (var2.equalsIgnoreCase("true")) {
         return true;
      } else {
         throw new RuntimeException("Value of " + var0 + " must either be 'true' or 'false'");
      }
   }

   static String toString(byte[] var0) {
      return sun.security.util.Debug.toString(var0);
   }
}
