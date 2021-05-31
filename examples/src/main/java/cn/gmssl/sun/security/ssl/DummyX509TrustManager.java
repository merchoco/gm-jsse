package cn.gmssl.sun.security.ssl;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

final class DummyX509TrustManager extends X509ExtendedTrustManager implements X509TrustManager {
   static final X509TrustManager INSTANCE = new DummyX509TrustManager();

   public void checkClientTrusted(X509Certificate[] var1, String var2) throws CertificateException {
      throw new CertificateException("No X509TrustManager implementation avaiable");
   }

   public void checkServerTrusted(X509Certificate[] var1, String var2) throws CertificateException {
      throw new CertificateException("No X509TrustManager implementation available");
   }

   public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
   }

   public void checkClientTrusted(X509Certificate[] var1, String var2, Socket var3) throws CertificateException {
      throw new CertificateException("No X509TrustManager implementation available");
   }

   public void checkServerTrusted(X509Certificate[] var1, String var2, Socket var3) throws CertificateException {
      throw new CertificateException("No X509TrustManager implementation available");
   }

   public void checkClientTrusted(X509Certificate[] var1, String var2, SSLEngine var3) throws CertificateException {
      throw new CertificateException("No X509TrustManager implementation available");
   }

   public void checkServerTrusted(X509Certificate[] var1, String var2, SSLEngine var3) throws CertificateException {
      throw new CertificateException("No X509TrustManager implementation available");
   }
}
