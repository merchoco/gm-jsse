package cn.gmssl.com.sun.net.ssl.internal.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public abstract class X509ExtendedTrustManager implements X509TrustManager {
   public abstract void checkClientTrusted(X509Certificate[] var1, String var2, String var3, String var4) throws CertificateException;

   public abstract void checkServerTrusted(X509Certificate[] var1, String var2, String var3, String var4) throws CertificateException;
}
