package cn.gmssl.sun.security.ssl;

import cn.gmssl.security.util.HostnameChecker;
import cn.gmssl.sun.security.validator.KeyStores;
import cn.gmssl.sun.security.validator.Validator;
import java.net.Socket;
import java.security.AlgorithmConstraints;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

final class X509TrustManagerImpl extends X509ExtendedTrustManager implements X509TrustManager {
   private final String validatorType;
   private final Collection<X509Certificate> trustedCerts;
   private final PKIXBuilderParameters pkixParams;
   private volatile Validator clientValidator;
   private volatile Validator serverValidator;
   private static final Debug debug = Debug.getInstance("ssl");

   X509TrustManagerImpl(String var1, KeyStore var2) throws KeyStoreException {
      this.validatorType = var1;
      this.pkixParams = null;
      if (var2 == null) {
         this.trustedCerts = Collections.emptySet();
      } else {
         this.trustedCerts = KeyStores.getTrustedCerts(var2);
      }

      this.showTrustedCerts();
   }

   X509TrustManagerImpl(String var1, PKIXBuilderParameters var2) {
      this.validatorType = var1;
      this.pkixParams = var2;
      Validator var3 = this.getValidator("tls server");
      this.trustedCerts = var3.getTrustedCertificates();
      this.serverValidator = var3;
      this.showTrustedCerts();
   }

   public void checkClientTrusted(X509Certificate[] var1, String var2) throws CertificateException {
      this.checkTrusted(var1, var2, (Socket)null, true);
   }

   public void checkServerTrusted(X509Certificate[] var1, String var2) throws CertificateException {
      this.checkTrusted(var1, var2, (Socket)null, false);
   }

   public X509Certificate[] getAcceptedIssuers() {
      X509Certificate[] var1 = new X509Certificate[this.trustedCerts.size()];
      this.trustedCerts.toArray(var1);
      return var1;
   }

   public void checkClientTrusted(X509Certificate[] var1, String var2, Socket var3) throws CertificateException {
      this.checkTrusted(var1, var2, var3, true);
   }

   public void checkServerTrusted(X509Certificate[] var1, String var2, Socket var3) throws CertificateException {
      this.checkTrusted(var1, var2, var3, false);
   }

   public void checkClientTrusted(X509Certificate[] var1, String var2, SSLEngine var3) throws CertificateException {
      this.checkTrusted(var1, var2, var3, true);
   }

   public void checkServerTrusted(X509Certificate[] var1, String var2, SSLEngine var3) throws CertificateException {
      this.checkTrusted(var1, var2, var3, false);
   }

   private Validator checkTrustedInit(X509Certificate[] var1, String var2, boolean var3) {
      if (var1 != null && var1.length != 0) {
         if (var2 != null && var2.length() != 0) {
            Validator var4 = null;
            if (var3) {
               var4 = this.clientValidator;
               if (var4 == null) {
                  synchronized(this) {
                     var4 = this.clientValidator;
                     if (var4 == null) {
                        var4 = this.getValidator("tls client");
                        this.clientValidator = var4;
                     }
                  }
               }
            } else {
               var4 = this.serverValidator;
               if (var4 == null) {
                  synchronized(this) {
                     var4 = this.serverValidator;
                     if (var4 == null) {
                        var4 = this.getValidator("tls server");
                        this.serverValidator = var4;
                     }
                  }
               }
            }

            return var4;
         } else {
            throw new IllegalArgumentException("null or zero-length authentication type");
         }
      } else {
         throw new IllegalArgumentException("null or zero-length certificate chain");
      }
   }

   private void checkTrusted(X509Certificate[] var1, String var2, Socket var3, boolean var4) throws CertificateException {
      Validator var5 = this.checkTrustedInit(var1, var2, var4);
      SSLAlgorithmConstraints var6 = null;
      SSLSocket var7;
      if (var3 != null && var3.isConnected() && var3 instanceof SSLSocket) {
         var7 = (SSLSocket)var3;
         SSLSession var8 = var7.getHandshakeSession();
         if (var8 == null) {
            throw new CertificateException("No handshake session");
         }

         String var9 = var7.getSSLParameters().getEndpointIdentificationAlgorithm();
         if (var9 != null && var9.length() != 0) {
            String var10 = var8.getPeerHost();
            checkIdentity(var10, var1[0], var9);
         }

         ProtocolVersion var14 = ProtocolVersion.valueOf(var8.getProtocol());
         if (var14.v >= ProtocolVersion.TLS12.v) {
            if (var8 instanceof ExtendedSSLSession) {
               ExtendedSSLSession var11 = (ExtendedSSLSession)var8;
               String[] var12 = var11.getLocalSupportedSignatureAlgorithms();
               var6 = new SSLAlgorithmConstraints(var7, var12, false);
            } else {
               var6 = new SSLAlgorithmConstraints(var7, false);
            }
         } else {
            var6 = new SSLAlgorithmConstraints(var7, false);
         }
      }

      var7 = null;
      X509Certificate[] var13;
      if (var4) {
         var13 = validate(var5, var1, var6, (String)null);
      } else {
         var13 = validate(var5, var1, var6, var2);
      }

      if (debug != null && Debug.isOn("trustmanager")) {
         System.out.println("Found trusted certificate:");
         System.out.println(var13[var13.length - 1]);
      }

   }

   private void checkTrusted(X509Certificate[] var1, String var2, SSLEngine var3, boolean var4) throws CertificateException {
      Validator var5 = this.checkTrustedInit(var1, var2, var4);
      SSLAlgorithmConstraints var6 = null;
      SSLSession var7;
      if (var3 != null) {
         var7 = var3.getHandshakeSession();
         if (var7 == null) {
            throw new CertificateException("No handshake session");
         }

         String var8 = var3.getSSLParameters().getEndpointIdentificationAlgorithm();
         if (var8 != null && var8.length() != 0) {
            String var9 = var7.getPeerHost();
            checkIdentity(var9, var1[0], var8);
         }

         ProtocolVersion var13 = ProtocolVersion.valueOf(var7.getProtocol());
         if (var13.v >= ProtocolVersion.TLS12.v) {
            if (var7 instanceof ExtendedSSLSession) {
               ExtendedSSLSession var10 = (ExtendedSSLSession)var7;
               String[] var11 = var10.getLocalSupportedSignatureAlgorithms();
               var6 = new SSLAlgorithmConstraints(var3, var11, false);
            } else {
               var6 = new SSLAlgorithmConstraints(var3, false);
            }
         } else {
            var6 = new SSLAlgorithmConstraints(var3, false);
         }
      }

      var7 = null;
      X509Certificate[] var12;
      if (var4) {
         var12 = validate(var5, var1, var6, (String)null);
      } else {
         var12 = validate(var5, var1, var6, var2);
      }

      if (debug != null && Debug.isOn("trustmanager")) {
         System.out.println("Found trusted certificate:");
         System.out.println(var12[var12.length - 1]);
      }

   }

   private void showTrustedCerts() {
      if (debug != null && Debug.isOn("trustmanager")) {
         Iterator var2 = this.trustedCerts.iterator();

         while(var2.hasNext()) {
            X509Certificate var1 = (X509Certificate)var2.next();
            System.out.println("adding as trusted cert:");
            System.out.println("  Subject: " + var1.getSubjectX500Principal());
            System.out.println("  Issuer:  " + var1.getIssuerX500Principal());
            System.out.println("  Algorithm: " + var1.getPublicKey().getAlgorithm() + "; Serial number: 0x" + var1.getSerialNumber().toString(16));
            System.out.println("  Valid from " + var1.getNotBefore() + " until " + var1.getNotAfter());
            System.out.println();
         }
      }

   }

   private Validator getValidator(String var1) {
      Validator var2;
      if (this.pkixParams == null) {
         var2 = Validator.getInstance(this.validatorType, var1, this.trustedCerts);
      } else {
         var2 = Validator.getInstance(this.validatorType, var1, this.pkixParams);
      }

      return var2;
   }

   private static X509Certificate[] validate(Validator var0, X509Certificate[] var1, AlgorithmConstraints var2, String var3) throws CertificateException {
      Object var4 = JsseJce.beginFipsProvider();

      X509Certificate[] var6;
      try {
         var6 = var0.validate(var1, (Collection)null, var2, var3);
      } finally {
         JsseJce.endFipsProvider(var4);
      }

      return var6;
   }

   static void checkIdentity(String var0, X509Certificate var1, String var2) throws CertificateException {
      if (var2 != null && var2.length() != 0) {
         if (var0 != null && var0.startsWith("[") && var0.endsWith("]")) {
            var0 = var0.substring(1, var0.length() - 1);
         }

         if (var2.equalsIgnoreCase("HTTPS")) {
            HostnameChecker.getInstance((byte)1).match(var0, var1);
         } else {
            if (!var2.equalsIgnoreCase("LDAP") && !var2.equalsIgnoreCase("LDAPS")) {
               throw new CertificateException("Unknown identification algorithm: " + var2);
            }

            HostnameChecker.getInstance((byte)2).match(var0, var1);
         }
      }

   }
}
