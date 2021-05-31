package cn.gmssl.sun.security.ssl;

import cn.gmssl.jsse.provider.GMConf;
import java.io.FileInputStream;
import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.PrivilegedExceptionAction;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public abstract class SSLContextImpl extends SSLContextSpi {
   private static final Debug debug = Debug.getInstance("ssl");
   private final EphemeralKeyManager ephemeralKeyManager = new EphemeralKeyManager();
   private final SSLSessionContextImpl clientCache = new SSLSessionContextImpl();
   private final SSLSessionContextImpl serverCache = new SSLSessionContextImpl();
   private boolean isInitialized;
   private X509ExtendedKeyManager keyManager;
   private X509TrustManager trustManager;
   private SecureRandom secureRandom;
   private AlgorithmConstraints defaultAlgorithmConstraints = new SSLAlgorithmConstraints((AlgorithmConstraints)null);
   private ProtocolList defaultServerProtocolList;
   private ProtocolList defaultClientProtocolList;
   private ProtocolList supportedProtocolList;
   private CipherSuiteList defaultServerCipherSuiteList;
   private CipherSuiteList defaultClientCipherSuiteList;
   private CipherSuiteList supportedCipherSuiteList;

   protected void engineInit(KeyManager[] var1, TrustManager[] var2, SecureRandom var3) throws KeyManagementException {
      this.isInitialized = false;
      this.keyManager = this.chooseKeyManager(var1);
      if (var2 == null) {
         try {
            TrustManagerFactory var4 = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            var4.init((KeyStore)null);
            var2 = var4.getTrustManagers();
         } catch (Exception var5) {
            ;
         }
      }

      this.trustManager = this.chooseTrustManager(var2);
      if (var3 == null) {
         this.secureRandom = JsseJce.getSecureRandom();
      } else {
         if (MyJSSE.isFIPS() && var3.getProvider() != MyJSSE.cryptoProvider) {
            throw new KeyManagementException("FIPS mode: SecureRandom must be from provider " + MyJSSE.cryptoProvider.getName());
         }

         this.secureRandom = var3;
      }

      if (debug != null && Debug.isOn("sslctx")) {
         System.out.println("trigger seeding of SecureRandom");
      }

      this.secureRandom.nextInt();
      if (debug != null && Debug.isOn("sslctx")) {
         System.out.println("done seeding SecureRandom");
      }

      this.isInitialized = true;
   }

   private X509TrustManager chooseTrustManager(TrustManager[] var1) throws KeyManagementException {
      for(int var2 = 0; var1 != null && var2 < var1.length; ++var2) {
         if (var1[var2] instanceof X509TrustManager) {
            if (MyJSSE.isFIPS() && !(var1[var2] instanceof X509TrustManagerImpl)) {
               throw new KeyManagementException("FIPS mode: only SunJSSE TrustManagers may be used");
            }

            if (var1[var2] instanceof X509ExtendedTrustManager) {
               return (X509TrustManager)var1[var2];
            }

            return new AbstractTrustManagerWrapper((X509TrustManager)var1[var2]);
         }
      }

      return DummyX509TrustManager.INSTANCE;
   }

   private X509ExtendedKeyManager chooseKeyManager(KeyManager[] var1) throws KeyManagementException {
      for(int var2 = 0; var1 != null && var2 < var1.length; ++var2) {
         KeyManager var3 = var1[var2];
         if (var3 instanceof X509KeyManager) {
            if (MyJSSE.isFIPS()) {
               if (!(var3 instanceof X509KeyManagerImpl) && !(var3 instanceof SunX509KeyManagerImpl)) {
                  throw new KeyManagementException("FIPS mode: only SunJSSE KeyManagers may be used");
               }

               return (X509ExtendedKeyManager)var3;
            }

            if (var3 instanceof X509ExtendedKeyManager) {
               return (X509ExtendedKeyManager)var3;
            }

            if (debug != null && Debug.isOn("sslctx")) {
               System.out.println("X509KeyManager passed to SSLContext.init():  need an X509ExtendedKeyManager for SSLEngine use");
            }

            return new AbstractKeyManagerWrapper((X509KeyManager)var3);
         }
      }

      return DummyX509KeyManager.INSTANCE;
   }

   protected SSLSocketFactory engineGetSocketFactory() {
      if (!this.isInitialized) {
         throw new IllegalStateException("SSLContextImpl is not initialized");
      } else {
         return new SSLSocketFactoryImpl(this);
      }
   }

   protected SSLServerSocketFactory engineGetServerSocketFactory() {
      if (!this.isInitialized) {
         throw new IllegalStateException("SSLContext is not initialized");
      } else {
         return new SSLServerSocketFactoryImpl(this);
      }
   }

   protected SSLEngine engineCreateSSLEngine() {
      if (!this.isInitialized) {
         throw new IllegalStateException("SSLContextImpl is not initialized");
      } else {
         return new SSLEngineImpl(this);
      }
   }

   protected SSLEngine engineCreateSSLEngine(String var1, int var2) {
      if (!this.isInitialized) {
         throw new IllegalStateException("SSLContextImpl is not initialized");
      } else {
         return new SSLEngineImpl(this, var1, var2);
      }
   }

   protected SSLSessionContext engineGetClientSessionContext() {
      return this.clientCache;
   }

   protected SSLSessionContext engineGetServerSessionContext() {
      return this.serverCache;
   }

   SecureRandom getSecureRandom() {
      return this.secureRandom;
   }

   X509ExtendedKeyManager getX509KeyManager() {
      return this.keyManager;
   }

   X509TrustManager getX509TrustManager() {
      return this.trustManager;
   }

   EphemeralKeyManager getEphemeralKeyManager() {
      return this.ephemeralKeyManager;
   }

   abstract SSLParameters getDefaultServerSSLParams();

   abstract SSLParameters getDefaultClientSSLParams();

   abstract SSLParameters getSupportedSSLParams();

   ProtocolList getSuportedProtocolList() {
      if (this.supportedProtocolList == null) {
         this.supportedProtocolList = new ProtocolList(this.getSupportedSSLParams().getProtocols());
      }

      return this.supportedProtocolList;
   }

   ProtocolList getDefaultProtocolList(boolean var1) {
      if (var1) {
         if (this.defaultServerProtocolList == null) {
            this.defaultServerProtocolList = new ProtocolList(this.getDefaultServerSSLParams().getProtocols());
         }

         if (GMConf.debug) {
            System.out.println("defaultServerProtocolList=" + this.defaultServerProtocolList);
         }

         return this.defaultServerProtocolList;
      } else {
         if (this.defaultClientProtocolList == null) {
            this.defaultClientProtocolList = new ProtocolList(this.getDefaultClientSSLParams().getProtocols());
         }

         if (GMConf.debug) {
            System.out.println("defaultServerProtocolList=" + this.defaultServerProtocolList);
         }

         return this.defaultClientProtocolList;
      }
   }

   CipherSuiteList getSuportedCipherSuiteList() {
      this.clearAvailableCache();
      if (this.supportedCipherSuiteList == null) {
         this.supportedCipherSuiteList = this.getApplicableCipherSuiteList(this.getSuportedProtocolList(), false);
      }

      return this.supportedCipherSuiteList;
   }

   CipherSuiteList getDefaultCipherSuiteList(boolean var1) {
      if (var1) {
         if (this.defaultServerCipherSuiteList == null) {
            this.defaultServerCipherSuiteList = this.getApplicableCipherSuiteList(this.getDefaultProtocolList(true), true);
         }

         if (GMConf.debug) {
            System.out.println("defaultServerCipherSuiteList=" + this.defaultServerCipherSuiteList);
         }

         return this.defaultServerCipherSuiteList;
      } else {
         if (this.defaultClientCipherSuiteList == null) {
            this.defaultClientCipherSuiteList = this.getApplicableCipherSuiteList(this.getDefaultProtocolList(false), true);
         }

         if (GMConf.debug) {
            System.out.println("defaultClientCipherSuiteList=" + this.defaultClientCipherSuiteList);
         }

         return this.defaultClientCipherSuiteList;
      }
   }

   boolean isDefaultProtocolList(ProtocolList var1) {
      return var1 == this.defaultServerProtocolList || var1 == this.defaultClientProtocolList;
   }

   private CipherSuiteList getApplicableCipherSuiteList(ProtocolList var1, boolean var2) {
      if (GMConf.debug) {
         System.out.println("getApplicableCipherSuiteList protocols=" + var1);
      }

      if (GMConf.debug) {
         System.out.println("getApplicableCipherSuiteList onlyEnabled=" + var2);
      }

      short var3 = 1;
      if (var2) {
         var3 = 300;
      }

      Collection var4 = CipherSuite.allowedCipherSuites();
      ArrayList var5 = new ArrayList();
      if (!var1.collection().isEmpty() && var1.min.v != ProtocolVersion.NONE.v) {
         Iterator var7 = var4.iterator();

         label87:
         while(true) {
            while(true) {
               while(true) {
                  if (!var7.hasNext()) {
                     break label87;
                  }

                  CipherSuite var6 = (CipherSuite)var7.next();
                  if (GMConf.debug) {
                     System.out.println("suite.allowed=" + var6.allowed + ",suite.priority=" + var6.priority + ",minPriority=" + var3);
                  }

                  if (var6.allowed && var6.priority >= var3) {
                     if (GMConf.debug) {
                        System.out.println("suite.isAvailable()=" + var6.isAvailable() + ",suite.obsoleted=" + var6.obsoleted + ",protocols.min.v=" + var1.min.v + ",suite.supported=" + var6.supported + ",protocols.max.v=" + var1.max.v);
                     }

                     if (var6.isAvailable() && var6.obsoleted > var1.min.v && var6.supported <= var1.max.v) {
                        if (this.defaultAlgorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), var6.name, (AlgorithmParameters)null)) {
                           if (GMConf.debug) {
                              System.out.println("yes cipher suite: " + var6);
                           }

                           var5.add(var6);
                        } else if (GMConf.debug) {
                           System.out.println("yes cipher suite: " + var6);
                        }
                     } else if (debug != null && Debug.isOn("sslctx") && Debug.isOn("verbose")) {
                        if (var6.obsoleted <= var1.min.v) {
                           System.out.println("Ignoring obsoleted cipher suite: " + var6);
                        } else if (var6.supported > var1.max.v) {
                           System.out.println("suite.supported=" + var6.supported + "protocols.max.v=" + var1.max.v);
                           System.out.println("Ignoring unsupported cipher suiteC: " + var6);
                        } else {
                           System.out.println("Ignoring unavailable cipher suite: " + var6);
                        }
                     }
                  } else if (GMConf.debug) {
                     System.out.println("not allowed cipher suite: " + var6);
                  }
               }
            }
         }
      }

      if (GMConf.debug) {
         System.out.println("getApplicableCipherSuiteList suites=" + var5);
      }

      CipherSuiteList var9 = new CipherSuiteList(var5);
      if (GMConf.debug) {
         Iterator var8 = var9.collection().iterator();

         while(var8.hasNext()) {
            CipherSuite var10 = (CipherSuite)var8.next();
            System.out.println("getApplicableCipherSuiteList suite=" + var10);
         }
      }

      return var9;
   }

   synchronized void clearAvailableCache() {
      this.supportedCipherSuiteList = null;
      this.defaultServerCipherSuiteList = null;
      this.defaultClientCipherSuiteList = null;
      CipherSuite.BulkCipher.clearAvailableCache();
      JsseJce.clearEcAvailable();
   }

   private static class ConservativeSSLContext extends SSLContextImpl {
      private static SSLParameters defaultServerSSLParams;
      private static SSLParameters defaultClientSSLParams;
      private static SSLParameters supportedSSLParams;

      static {
         if (MyJSSE.isFIPS()) {
            supportedSSLParams = new SSLParameters();
            supportedSSLParams.setProtocols(new String[]{ProtocolVersion.TLS10.name, ProtocolVersion.GMSSL10.name, ProtocolVersion.GMSSL11.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.TLS10.name});
         } else {
            supportedSSLParams = new SSLParameters();
            supportedSSLParams.setProtocols(new String[]{ProtocolVersion.SSL20Hello.name, ProtocolVersion.SSL30.name, ProtocolVersion.TLS10.name, ProtocolVersion.GMSSL10.name, ProtocolVersion.GMSSL11.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.SSL30.name, ProtocolVersion.TLS10.name});
         }

      }

      private ConservativeSSLContext() {
      }

      SSLParameters getDefaultServerSSLParams() {
         return defaultServerSSLParams;
      }

      SSLParameters getDefaultClientSSLParams() {
         return defaultClientSSLParams;
      }

      SSLParameters getSupportedSSLParams() {
         return supportedSSLParams;
      }

      // $FF: synthetic method
      ConservativeSSLContext(SSLContextImpl.ConservativeSSLContext var1) {
         this();
      }
   }

   public static final class DefaultSSLContext extends SSLContextImpl.ConservativeSSLContext {
      private static final String NONE = "NONE";
      private static final String P11KEYSTORE = "PKCS11";
      private static volatile SSLContextImpl defaultImpl;
      private static TrustManager[] defaultTrustManagers;
      private static KeyManager[] defaultKeyManagers;

      public DefaultSSLContext() throws Exception {
         super((SSLContextImpl.ConservativeSSLContext)null);

         try {
            super.engineInit(getDefaultKeyManager(), getDefaultTrustManager(), (SecureRandom)null);
         } catch (Exception var2) {
            if (SSLContextImpl.debug != null && Debug.isOn("defaultctx")) {
               System.out.println("default context init failed: " + var2);
            }

            throw var2;
         }

         if (defaultImpl == null) {
            defaultImpl = this;
         }

      }

      protected void engineInit(KeyManager[] var1, TrustManager[] var2, SecureRandom var3) throws KeyManagementException {
         throw new KeyManagementException("Default SSLContext is initialized automatically");
      }

      static synchronized SSLContextImpl getDefaultImpl() throws Exception {
         if (defaultImpl == null) {
            new SSLContextImpl.DefaultSSLContext();
         }

         return defaultImpl;
      }

      private static synchronized TrustManager[] getDefaultTrustManager() throws Exception {
         if (defaultTrustManagers != null) {
            return defaultTrustManagers;
         } else {
            KeyStore var0 = TrustManagerFactoryImpl.getCacertsKeyStore("defaultctx");
            TrustManagerFactory var1 = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            var1.init(var0);
            defaultTrustManagers = var1.getTrustManagers();
            return defaultTrustManagers;
         }
      }

      private static synchronized KeyManager[] getDefaultKeyManager() throws Exception {
         if (defaultKeyManagers != null) {
            return defaultKeyManagers;
         } else {
            final HashMap var0 = new HashMap();
            AccessController.doPrivileged(new PrivilegedExceptionAction<Object>() {
               public Object run() throws Exception {
                  var0.put("keyStore", System.getProperty("javax.net.ssl.keyStore", ""));
                  var0.put("keyStoreType", System.getProperty("javax.net.ssl.keyStoreType", KeyStore.getDefaultType()));
                  var0.put("keyStoreProvider", System.getProperty("javax.net.ssl.keyStoreProvider", ""));
                  var0.put("keyStorePasswd", System.getProperty("javax.net.ssl.keyStorePassword", ""));
                  return null;
               }
            });
            final String var1 = (String)var0.get("keyStore");
            String var2 = (String)var0.get("keyStoreType");
            String var3 = (String)var0.get("keyStoreProvider");
            if (SSLContextImpl.debug != null && Debug.isOn("defaultctx")) {
               System.out.println("keyStore is : " + var1);
               System.out.println("keyStore type is : " + var2);
               System.out.println("keyStore provider is : " + var3);
            }

            if ("PKCS11".equals(var2) && !"NONE".equals(var1)) {
               throw new IllegalArgumentException("if keyStoreType is PKCS11, then keyStore must be NONE");
            } else {
               FileInputStream var4 = null;
               if (var1.length() != 0 && !"NONE".equals(var1)) {
                  var4 = (FileInputStream)AccessController.doPrivileged(new PrivilegedExceptionAction<FileInputStream>() {
                     public FileInputStream run() throws Exception {
                        return new FileInputStream(var1);
                     }
                  });
               }

               String var5 = (String)var0.get("keyStorePasswd");
               char[] var6 = null;
               if (var5.length() != 0) {
                  var6 = var5.toCharArray();
               }

               KeyStore var7 = null;
               if (var2.length() != 0) {
                  if (SSLContextImpl.debug != null && Debug.isOn("defaultctx")) {
                     System.out.println("init keystore");
                  }

                  if (var3.length() == 0) {
                     var7 = KeyStore.getInstance(var2);
                  } else {
                     var7 = KeyStore.getInstance(var2, var3);
                  }

                  var7.load(var4, var6);
               }

               if (var4 != null) {
                  var4.close();
                  var4 = null;
               }

               if (SSLContextImpl.debug != null && Debug.isOn("defaultctx")) {
                  System.out.println("init keymanager of type " + KeyManagerFactory.getDefaultAlgorithm());
               }

               KeyManagerFactory var8 = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
               if ("PKCS11".equals(var2)) {
                  var8.init(var7, (char[])null);
               } else {
                  var8.init(var7, var6);
               }

               defaultKeyManagers = var8.getKeyManagers();
               return defaultKeyManagers;
            }
         }
      }
   }

   public static final class GBTLS10Context extends SSLContextImpl {
      private static SSLParameters defaultServerSSLParams;
      private static SSLParameters defaultClientSSLParams;
      private static SSLParameters supportedSSLParams;

      static {
         if (MyJSSE.isFIPS()) {
            supportedSSLParams = new SSLParameters();
            supportedSSLParams.setProtocols(new String[]{ProtocolVersion.TLS10.name, ProtocolVersion.GMSSL10.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.GMSSL10.name});
         } else {
            supportedSSLParams = new SSLParameters();
            supportedSSLParams.setProtocols(new String[]{ProtocolVersion.SSL20Hello.name, ProtocolVersion.SSL30.name, ProtocolVersion.TLS10.name, ProtocolVersion.GMSSL10.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.GMSSL10.name});
         }

      }

      SSLParameters getDefaultServerSSLParams() {
         return defaultServerSSLParams;
      }

      SSLParameters getDefaultClientSSLParams() {
         return defaultClientSSLParams;
      }

      SSLParameters getSupportedSSLParams() {
         return supportedSSLParams;
      }
   }

   public static final class GBTLS11Context extends SSLContextImpl {
      private static SSLParameters defaultServerSSLParams;
      private static SSLParameters defaultClientSSLParams;
      private static SSLParameters supportedSSLParams;

      static {
         if (MyJSSE.isFIPS()) {
            supportedSSLParams = new SSLParameters();
            supportedSSLParams.setProtocols(new String[]{ProtocolVersion.TLS10.name, ProtocolVersion.GMSSL10.name, ProtocolVersion.GMSSL11.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.GMSSL11.name});
         } else {
            supportedSSLParams = new SSLParameters();
            if (GMConf.adaptive) {
               supportedSSLParams.setProtocols(new String[]{ProtocolVersion.SSL20Hello.name, ProtocolVersion.SSL30.name, ProtocolVersion.TLS10.name, ProtocolVersion.GMSSL10.name, ProtocolVersion.GMSSL11.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            } else {
               supportedSSLParams.setProtocols(new String[]{ProtocolVersion.GMSSL11.name});
            }

            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            if (GMConf.adaptive) {
               if (GMConf.debug) {
                  System.out.println("ADAPTIVE yes");
               }

               defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.GMSSL11.name, ProtocolVersion.TLS12.name});
            } else {
               if (GMConf.debug) {
                  System.out.println("ADAPTIVE no");
               }

               defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.GMSSL11.name});
            }
         }

      }

      SSLParameters getDefaultServerSSLParams() {
         return defaultServerSSLParams;
      }

      SSLParameters getDefaultClientSSLParams() {
         return defaultClientSSLParams;
      }

      SSLParameters getSupportedSSLParams() {
         return supportedSSLParams;
      }
   }

   public static final class TLS10Context extends SSLContextImpl.ConservativeSSLContext {
      public TLS10Context() {
         super((SSLContextImpl.ConservativeSSLContext)null);
      }
   }

   public static final class TLS11Context extends SSLContextImpl {
      private static SSLParameters defaultServerSSLParams;
      private static SSLParameters defaultClientSSLParams;
      private static SSLParameters supportedSSLParams;

      static {
         if (MyJSSE.isFIPS()) {
            supportedSSLParams = new SSLParameters();
            supportedSSLParams.setProtocols(new String[]{ProtocolVersion.TLS10.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.TLS10.name, ProtocolVersion.TLS11.name});
         } else {
            supportedSSLParams = new SSLParameters();
            supportedSSLParams.setProtocols(new String[]{ProtocolVersion.SSL20Hello.name, ProtocolVersion.SSL30.name, ProtocolVersion.TLS10.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.SSL30.name, ProtocolVersion.TLS10.name, ProtocolVersion.TLS11.name});
         }

      }

      SSLParameters getDefaultServerSSLParams() {
         return defaultServerSSLParams;
      }

      SSLParameters getDefaultClientSSLParams() {
         return defaultClientSSLParams;
      }

      SSLParameters getSupportedSSLParams() {
         return supportedSSLParams;
      }
   }

   public static final class TLS12Context extends SSLContextImpl {
      private static SSLParameters defaultServerSSLParams;
      private static SSLParameters defaultClientSSLParams;
      private static SSLParameters supportedSSLParams;

      static {
         if (MyJSSE.isFIPS()) {
            supportedSSLParams = new SSLParameters();
            supportedSSLParams.setProtocols(new String[]{ProtocolVersion.TLS10.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.TLS10.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
         } else {
            supportedSSLParams = new SSLParameters();
            supportedSSLParams.setProtocols(new String[]{ProtocolVersion.SSL20Hello.name, ProtocolVersion.SSL30.name, ProtocolVersion.TLS10.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
            defaultServerSSLParams = supportedSSLParams;
            defaultClientSSLParams = new SSLParameters();
            defaultClientSSLParams.setProtocols(new String[]{ProtocolVersion.SSL30.name, ProtocolVersion.TLS10.name, ProtocolVersion.TLS11.name, ProtocolVersion.TLS12.name});
         }

      }

      SSLParameters getDefaultServerSSLParams() {
         return defaultServerSSLParams;
      }

      SSLParameters getDefaultClientSSLParams() {
         return defaultClientSSLParams;
      }

      SSLParameters getSupportedSSLParams() {
         return supportedSSLParams;
      }
   }
}
