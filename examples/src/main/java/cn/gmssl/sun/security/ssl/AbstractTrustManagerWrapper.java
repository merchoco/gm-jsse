package cn.gmssl.sun.security.ssl;

import cn.gmssl.sun.security.provider.certpath.AlgorithmChecker;
import java.net.Socket;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

final class AbstractTrustManagerWrapper extends X509ExtendedTrustManager implements X509TrustManager {
   private final X509TrustManager tm;

   AbstractTrustManagerWrapper(X509TrustManager var1) {
      this.tm = var1;
   }

   public void checkClientTrusted(X509Certificate[] var1, String var2) throws CertificateException {
      this.tm.checkClientTrusted(var1, var2);
   }

   public void checkServerTrusted(X509Certificate[] var1, String var2) throws CertificateException {
      this.tm.checkServerTrusted(var1, var2);
   }

   public X509Certificate[] getAcceptedIssuers() {
      return this.tm.getAcceptedIssuers();
   }

   public void checkClientTrusted(X509Certificate[] var1, String var2, Socket var3) throws CertificateException {
      this.tm.checkClientTrusted(var1, var2);
      this.checkAdditionalTrust(var1, var2, var3, true);
   }

   public void checkServerTrusted(X509Certificate[] var1, String var2, Socket var3) throws CertificateException {
      this.tm.checkServerTrusted(var1, var2);
      this.checkAdditionalTrust(var1, var2, var3, false);
   }

   public void checkClientTrusted(X509Certificate[] var1, String var2, SSLEngine var3) throws CertificateException {
      this.tm.checkClientTrusted(var1, var2);
      this.checkAdditionalTrust(var1, var2, var3, true);
   }

   public void checkServerTrusted(X509Certificate[] var1, String var2, SSLEngine var3) throws CertificateException {
      this.tm.checkServerTrusted(var1, var2);
      this.checkAdditionalTrust(var1, var2, var3, false);
   }

   private void checkAdditionalTrust(X509Certificate[] var1, String var2, Socket var3, boolean var4) throws CertificateException {
      if (var3 != null && var3.isConnected() && var3 instanceof SSLSocket) {
         SSLSocket var5 = (SSLSocket)var3;
         SSLSession var6 = var5.getHandshakeSession();
         if (var6 == null) {
            throw new CertificateException("No handshake session");
         }

         String var7 = var5.getSSLParameters().getEndpointIdentificationAlgorithm();
         if (var7 != null && var7.length() != 0) {
            String var8 = var6.getPeerHost();
            X509TrustManagerImpl.checkIdentity(var8, var1[0], var7);
         }

         ProtocolVersion var14 = ProtocolVersion.valueOf(var6.getProtocol());
         SSLAlgorithmConstraints var9 = null;
         if (var14.v >= ProtocolVersion.TLS12.v) {
            if (var6 instanceof ExtendedSSLSession) {
               ExtendedSSLSession var10 = (ExtendedSSLSession)var6;
               String[] var11 = var10.getLocalSupportedSignatureAlgorithms();
               var9 = new SSLAlgorithmConstraints(var5, var11, true);
            } else {
               var9 = new SSLAlgorithmConstraints(var5, true);
            }
         } else {
            var9 = new SSLAlgorithmConstraints(var5, true);
         }

         AlgorithmChecker var15 = new AlgorithmChecker(var9);

         try {
            var15.init(false);

            for(int var16 = var1.length - 1; var16 >= 0; --var16) {
               X509Certificate var12 = var1[var16];
               var15.check((Certificate)var12, (Collection)Collections.emptySet());
            }
         } catch (CertPathValidatorException var13) {
            throw new CertificateException("Certificates does not conform to algorithm constraints");
         }
      }

   }

   private void checkAdditionalTrust(X509Certificate[] var1, String var2, SSLEngine var3, boolean var4) throws CertificateException {
      if (var3 != null) {
         SSLSession var5 = var3.getHandshakeSession();
         if (var5 == null) {
            throw new CertificateException("No handshake session");
         }

         String var6 = var3.getSSLParameters().getEndpointIdentificationAlgorithm();
         if (var6 != null && var6.length() != 0) {
            String var7 = var5.getPeerHost();
            X509TrustManagerImpl.checkIdentity(var7, var1[0], var6);
         }

         ProtocolVersion var13 = ProtocolVersion.valueOf(var5.getProtocol());
         SSLAlgorithmConstraints var8 = null;
         if (var13.v >= ProtocolVersion.TLS12.v) {
            if (var5 instanceof ExtendedSSLSession) {
               ExtendedSSLSession var9 = (ExtendedSSLSession)var5;
               String[] var10 = var9.getLocalSupportedSignatureAlgorithms();
               var8 = new SSLAlgorithmConstraints(var3, var10, true);
            } else {
               var8 = new SSLAlgorithmConstraints(var3, true);
            }
         } else {
            var8 = new SSLAlgorithmConstraints(var3, true);
         }

         AlgorithmChecker var14 = new AlgorithmChecker(var8);

         try {
            var14.init(false);

            for(int var15 = var1.length - 1; var15 >= 0; --var15) {
               X509Certificate var11 = var1[var15];
               var14.check((Certificate)var11, (Collection)Collections.emptySet());
            }
         } catch (CertPathValidatorException var12) {
            throw new CertificateException("Certificates does not conform to algorithm constraints");
         }
      }

   }
}
