package cn.gmssl.security.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import sun.net.www.ParseUtil;

public class PolicyUtil {
   private static final String P11KEYSTORE = "PKCS11";
   private static final String NONE = "NONE";

   public static InputStream getInputStream(URL var0) throws IOException {
      if ("file".equals(var0.getProtocol())) {
         String var1 = var0.getFile().replace('/', File.separatorChar);
         var1 = ParseUtil.decode(var1);
         return new FileInputStream(var1);
      } else {
         return var0.openStream();
      }
   }

   public static KeyStore getKeyStore(URL var0, String var1, String var2, String var3, String var4, Debug var5) throws KeyStoreException, MalformedURLException, IOException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException {
      if (var1 == null) {
         throw new IllegalArgumentException("null KeyStore name");
      } else {
         char[] var6 = null;

         KeyStore var12;
         try {
            if (var2 == null) {
               var2 = KeyStore.getDefaultType();
            }

            if ("PKCS11".equalsIgnoreCase(var2) && !"NONE".equals(var1)) {
               throw new IllegalArgumentException("Invalid value (" + var1 + ") for keystore URL.  If the keystore type is \"" + "PKCS11" + "\", the keystore url must be \"" + "NONE" + "\"");
            }

            KeyStore var7;
            if (var3 != null) {
               var7 = KeyStore.getInstance(var2, var3);
            } else {
               var7 = KeyStore.getInstance(var2);
            }

            URL var8;
            if (var4 != null) {
               try {
                  var8 = new URL(var4);
               } catch (MalformedURLException var30) {
                  if (var0 == null) {
                     throw var30;
                  }

                  var8 = new URL(var0, var4);
               }

               if (var5 != null) {
                  var5.println("reading password" + var8);
               }

               InputStream var9 = null;

               try {
                  var9 = var8.openStream();
                  var6 = Password.readPassword(var9);
               } finally {
                  if (var9 != null) {
                     var9.close();
                  }

               }
            }

            if (!"NONE".equals(var1)) {
               var8 = null;

               try {
                  var8 = new URL(var1);
               } catch (MalformedURLException var31) {
                  if (var0 == null) {
                     throw var31;
                  }

                  var8 = new URL(var0, var1);
               }

               if (var5 != null) {
                  var5.println("reading keystore" + var8);
               }

               BufferedInputStream var33 = null;

               try {
                  var33 = new BufferedInputStream(getInputStream(var8));
                  var7.load(var33, var6);
               } finally {
                  var33.close();
               }

               var12 = var7;
               return var12;
            }

            var7.load((InputStream)null, var6);
            var12 = var7;
         } finally {
            if (var6 != null) {
               Arrays.fill(var6, ' ');
            }

         }

         return var12;
      }
   }
}
