package cn.gmssl.com.jsse;

import java.security.cert.X509Certificate;

public class SM2CertUtil {
   public static boolean signCert(X509Certificate var0) {
      boolean[] var1 = var0.getKeyUsage();
      return var1[0];
   }

   public static boolean encryptCert(X509Certificate var0) {
      boolean[] var1 = var0.getKeyUsage();
      return var1[2] || var1[3] || var1[4];
   }
}
