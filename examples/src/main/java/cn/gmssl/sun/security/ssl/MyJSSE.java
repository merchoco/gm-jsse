package cn.gmssl.sun.security.ssl;

import cn.gmssl.jsse.provider.GMJSSE;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;

public abstract class MyJSSE extends Provider {
   private static final long serialVersionUID = 3231825739635378733L;
   public static final String NAME = "GMJSSE";
   public static final String GMSSLv10 = "GMSSLv1.0";
   public static final String GMSSLv11 = "GMSSLv1.1";
   private static String info = "GM JSSE provider";
   private static String fipsInfo = "GM JSSE provider (FIPS mode crypto provider)";
   private static Boolean fips;
   static Provider cryptoProvider;

   protected static synchronized boolean isFIPS() {
      if (fips == null) {
         fips = false;
      }

      return fips;
   }

   private static synchronized void ensureFIPS(Provider var0) {
      if (fips == null) {
         fips = true;
         cryptoProvider = var0;
      } else {
         if (!fips) {
            throw new ProviderException("SunJSSE already initialized in non-FIPS mode");
         }

         if (cryptoProvider != var0) {
            throw new ProviderException("SunJSSE already initialized with FIPS crypto provider " + cryptoProvider);
         }
      }

   }

   protected MyJSSE() {
      super("GMJSSE", 1.0D, info);
      this.subclassCheck();
      if (Boolean.TRUE.equals(fips)) {
         throw new ProviderException("AbstractBigSSLJSSE is already initialized in FIPS mode");
      } else {
         this.registerAlgorithms(false);
      }
   }

   protected MyJSSE(Provider var1) {
      this((Provider)checkNull(var1), var1.getName());
   }

   protected MyJSSE(String var1) {
      this((Provider)null, (String)checkNull(var1));
   }

   private static <T> T checkNull(T var0) {
      if (var0 == null) {
         throw new ProviderException("cryptoProvider must not be null");
      } else {
         return var0;
      }
   }

   private MyJSSE(Provider var1, String var2) {
      super("SunJSSE", 1.6D, fipsInfo + var2 + ")");
      this.subclassCheck();
      if (var1 == null) {
         var1 = Security.getProvider(var2);
         if (var1 == null) {
            throw new ProviderException("Crypto provider not installed: " + var2);
         }
      }

      ensureFIPS(var1);
      this.registerAlgorithms(true);
   }

   private void registerAlgorithms(final boolean var1) {
      AccessController.doPrivileged(new PrivilegedAction<Object>() {
         public Object run() {
            MyJSSE.this.doRegister(var1);
            return null;
         }
      });
   }

   private void doRegister(boolean var1) {
      if (!var1) {
         this.put("KeyFactory.RSA", "sun.security.rsa.RSAKeyFactory");
         this.put("Alg.Alias.KeyFactory.1.2.840.113549.1.1", "RSA");
         this.put("Alg.Alias.KeyFactory.OID.1.2.840.113549.1.1", "RSA");
         this.put("KeyPairGenerator.RSA", "sun.security.rsa.RSAKeyPairGenerator");
         this.put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1", "RSA");
         this.put("Alg.Alias.KeyPairGenerator.OID.1.2.840.113549.1.1", "RSA");
         this.put("Signature.MD2withRSA", "sun.security.rsa.RSASignature$MD2withRSA");
         this.put("Alg.Alias.Signature.1.2.840.113549.1.1.2", "MD2withRSA");
         this.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.2", "MD2withRSA");
         this.put("Signature.MD5withRSA", "sun.security.rsa.RSASignature$MD5withRSA");
         this.put("Alg.Alias.Signature.1.2.840.113549.1.1.4", "MD5withRSA");
         this.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.4", "MD5withRSA");
         this.put("Signature.SHA1withRSA", "sun.security.rsa.RSASignature$SHA1withRSA");
         this.put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
         this.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", "SHA1withRSA");
         this.put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1withRSA");
         this.put("Alg.Alias.Signature.OID.1.3.14.3.2.29", "SHA1withRSA");
      }

      this.put("Signature.MD5andSHA1withRSA", "cn.gmssl.sun.security.ssl.RSASignature");
      this.put("KeyManagerFactory.SunX509", "cn.gmssl.sun.security.ssl.KeyManagerFactoryImpl$SunX509");
      this.put("KeyManagerFactory.NewSunX509", "cn.gmssl.sun.security.ssl.KeyManagerFactoryImpl$X509");
      this.put("Alg.Alias.KeyManagerFactory.PKIX", "NewSunX509");
      this.put("TrustManagerFactory.SunX509", "cn.gmssl.sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory");
      this.put("TrustManagerFactory.PKIX", "cn.gmssl.sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory");
      this.put("Alg.Alias.TrustManagerFactory.SunPKIX", "PKIX");
      this.put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
      this.put("Alg.Alias.TrustManagerFactory.X.509", "PKIX");
      this.put("SSLContext.TLSv1", "cn.gmssl.sun.security.ssl.SSLContextImpl$TLS10Context");
      this.put("Alg.Alias.SSLContext.TLS", "TLSv1");
      if (!var1) {
         this.put("Alg.Alias.SSLContext.SSL", "TLSv1");
         this.put("Alg.Alias.SSLContext.SSLv3", "TLSv1");
      }

      this.put("SSLContext.GMSSLv1.0", "cn.gmssl.sun.security.ssl.SSLContextImpl$GBTLS10Context");
      this.put("SSLContext.GMSSLv1.1", "cn.gmssl.sun.security.ssl.SSLContextImpl$GBTLS11Context");
/*      this.put("SSLContext.TLSv1.1", "cn.gmssl.sun.security.ssl.SSLContextImpl$TLS11Context");
      this.put("SSLContext.TLSv1.2", "cn.gmssl.sun.security.ssl.SSLContextImpl$TLS12Context");
      this.put("SSLContext.Default", "cn.gmssl.sun.security.ssl.SSLContextImpl$DefaultSSLContext");*/
      this.put("KeyStore.PKCS12", "org.bc.jce.provider.JDKPKCS12KeyStore$BCPKCS12KeyStore");
      this.put("KeyGenerator.SunTlsPrf", "cn.gmssl.com.sun.crypto.provider.TlsPrfGenerator$V10");
      this.put("KeyGenerator.SunTls12Prf", "cn.gmssl.com.sun.crypto.provider.TlsPrfGenerator$V12");
      this.put("KeyGenerator.GBTlsPrf", "cn.gmssl.com.jsse.GBTlsPrfGenerator");
      this.put("KeyGenerator.SunTlsMasterSecret", "cn.gmssl.com.sun.crypto.provider.TlsMasterSecretGenerator");
      this.put("Alg.Alias.KeyGenerator.SunTls12MasterSecret", "SunTlsMasterSecret");
      this.put("KeyGenerator.GBTlsMasterSecret", "cn.gmssl.com.jsse.GBTlsMasterSecretGenerator");
      this.put("KeyGenerator.SunTlsKeyMaterial", "cn.gmssl.com.sun.crypto.provider.TlsKeyMaterialGenerator");
      this.put("Alg.Alias.KeyGenerator.SunTls12KeyMaterial", "SunTlsKeyMaterial");
      this.put("KeyGenerator.GBTlsKeyMaterial", "cn.gmssl.com.jsse.GBTlsKeyMaterialGenerator");
      this.put("KeyGenerator.SunTlsRsaPremasterSecret", "cn.gmssl.com.sun.crypto.provider.TlsRsaPremasterSecretGenerator");
      this.put("Alg.Alias.KeyGenerator.SunTls12RsaPremasterSecret", "SunTlsRsaPremasterSecret");
   }

   private void subclassCheck() {
      if (this.getClass() != GMJSSE.class) {
         throw new AssertionError("Illegal subclass: " + this.getClass());
      }
   }

   protected final void finalize() throws Throwable {
      super.finalize();
   }
}
