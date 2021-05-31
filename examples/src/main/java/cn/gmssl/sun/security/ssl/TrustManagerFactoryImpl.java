package cn.gmssl.sun.security.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.CertPathParameters;
import java.security.cert.PKIXBuilderParameters;
import java.util.HashMap;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;

abstract class TrustManagerFactoryImpl extends TrustManagerFactorySpi {
   private static final Debug debug = Debug.getInstance("ssl");
   private X509TrustManager trustManager = null;
   private boolean isInitialized = false;

   protected void engineInit(KeyStore var1) throws KeyStoreException {
      if (var1 == null) {
         try {
            var1 = getCacertsKeyStore("trustmanager");
         } catch (SecurityException var3) {
            if (debug != null && Debug.isOn("trustmanager")) {
               System.out.println("SunX509: skip default keystore: " + var3);
            }
         } catch (Error var4) {
            if (debug != null && Debug.isOn("trustmanager")) {
               System.out.println("SunX509: skip default keystore: " + var4);
            }

            throw var4;
         } catch (RuntimeException var5) {
            if (debug != null && Debug.isOn("trustmanager")) {
               System.out.println("SunX509: skip default keystore: " + var5);
            }

            throw var5;
         } catch (Exception var6) {
            if (debug != null && Debug.isOn("trustmanager")) {
               System.out.println("SunX509: skip default keystore: " + var6);
            }

            throw new KeyStoreException("problem accessing trust store" + var6);
         }
      }

      this.trustManager = this.getInstance(var1);
      this.isInitialized = true;
   }

   abstract X509TrustManager getInstance(KeyStore var1) throws KeyStoreException;

   abstract X509TrustManager getInstance(ManagerFactoryParameters var1) throws InvalidAlgorithmParameterException;

   protected void engineInit(ManagerFactoryParameters var1) throws InvalidAlgorithmParameterException {
      this.trustManager = this.getInstance(var1);
      this.isInitialized = true;
   }

   protected TrustManager[] engineGetTrustManagers() {
      if (!this.isInitialized) {
         throw new IllegalStateException("TrustManagerFactoryImpl is not initialized");
      } else {
         return new TrustManager[]{this.trustManager};
      }
   }

   private static FileInputStream getFileInputStream(final File var0) throws Exception {
      return (FileInputStream)AccessController.doPrivileged(new PrivilegedExceptionAction<FileInputStream>() {
         public FileInputStream run() throws Exception {
            try {
               return var0.exists() ? new FileInputStream(var0) : null;
            } catch (FileNotFoundException var2) {
               return null;
            }
         }
      });
   }

   static KeyStore getCacertsKeyStore(String var0) throws Exception {
      String var1 = null;
      File var2 = null;
      FileInputStream var3 = null;
      final HashMap var6 = new HashMap();
      String var7 = File.separator;
      KeyStore var8 = null;
      AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            var6.put("trustStore", System.getProperty("javax.net.ssl.trustStore"));
            var6.put("javaHome", System.getProperty("java.home"));
            var6.put("trustStoreType", System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType()));
            var6.put("trustStoreProvider", System.getProperty("javax.net.ssl.trustStoreProvider", ""));
            var6.put("trustStorePasswd", System.getProperty("javax.net.ssl.trustStorePassword", ""));
            return null;
         }
      });
      var1 = (String)var6.get("trustStore");
      if (!"NONE".equals(var1)) {
         if (var1 != null) {
            var2 = new File(var1);
            var3 = getFileInputStream(var2);
         } else {
            String var9 = (String)var6.get("javaHome");
            var2 = new File(var9 + var7 + "lib" + var7 + "security" + var7 + "jssecacerts");
            if ((var3 = getFileInputStream(var2)) == null) {
               var2 = new File(var9 + var7 + "lib" + var7 + "security" + var7 + "cacerts");
               var3 = getFileInputStream(var2);
            }
         }

         if (var3 != null) {
            var1 = var2.getPath();
         } else {
            var1 = "No File Available, using empty keystore.";
         }
      }

      String var4 = (String)var6.get("trustStoreType");
      String var5 = (String)var6.get("trustStoreProvider");
      if (debug != null && Debug.isOn(var0)) {
         System.out.println("trustStore is: " + var1);
         System.out.println("trustStore type is : " + var4);
         System.out.println("trustStore provider is : " + var5);
      }

      if (var4.length() != 0) {
         if (debug != null && Debug.isOn(var0)) {
            System.out.println("init truststore");
         }

         if (var5.length() == 0) {
            var8 = KeyStore.getInstance(var4);
         } else {
            var8 = KeyStore.getInstance(var4, var5);
         }

         char[] var12 = null;
         String var10 = (String)var6.get("trustStorePasswd");
         if (var10.length() != 0) {
            var12 = var10.toCharArray();
         }

         var8.load(var3, var12);
         if (var12 != null) {
            for(int var11 = 0; var11 < var12.length; ++var11) {
               var12[var11] = 0;
            }
         }
      }

      if (var3 != null) {
         var3.close();
      }

      return var8;
   }

   public static final class PKIXFactory extends TrustManagerFactoryImpl {
      X509TrustManager getInstance(KeyStore var1) throws KeyStoreException {
         return new X509TrustManagerImpl("PKIX", var1);
      }

      X509TrustManager getInstance(ManagerFactoryParameters var1) throws InvalidAlgorithmParameterException {
         if (!(var1 instanceof CertPathTrustManagerParameters)) {
            throw new InvalidAlgorithmParameterException("Parameters must be CertPathTrustManagerParameters");
         } else {
            CertPathParameters var2 = ((CertPathTrustManagerParameters)var1).getParameters();
            if (!(var2 instanceof PKIXBuilderParameters)) {
               throw new InvalidAlgorithmParameterException("Encapsulated parameters must be PKIXBuilderParameters");
            } else {
               PKIXBuilderParameters var3 = (PKIXBuilderParameters)var2;
               return new X509TrustManagerImpl("PKIX", var3);
            }
         }
      }
   }

   public static final class SimpleFactory extends TrustManagerFactoryImpl {
      X509TrustManager getInstance(KeyStore var1) throws KeyStoreException {
         return new X509TrustManagerImpl("Simple", var1);
      }

      X509TrustManager getInstance(ManagerFactoryParameters var1) throws InvalidAlgorithmParameterException {
         throw new InvalidAlgorithmParameterException("SunX509 TrustManagerFactory does not use ManagerFactoryParameters");
      }
   }
}
