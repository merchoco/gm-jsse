package cn.gmssl.sun.security.validator;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public class KeyStores {
   public static Set<X509Certificate> getTrustedCerts(KeyStore var0) {
      HashSet var1 = new HashSet();

      try {
         Enumeration var2 = var0.aliases();

         while(var2.hasMoreElements()) {
            String var3 = (String)var2.nextElement();
            if (var0.isCertificateEntry(var3)) {
               Certificate var4 = var0.getCertificate(var3);
               if (var4 instanceof X509Certificate) {
                  var1.add((X509Certificate)var4);
               }
            } else if (var0.isKeyEntry(var3)) {
               Certificate[] var6 = var0.getCertificateChain(var3);
               if (var6 != null && var6.length > 0 && var6[0] instanceof X509Certificate) {
                  var1.add((X509Certificate)var6[0]);
               }
            }
         }
      } catch (KeyStoreException var5) {
         ;
      }

      return var1;
   }
}
