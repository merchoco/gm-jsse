package cn.gmssl.sun.security.ssl;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.Builder;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;

abstract class KeyManagerFactoryImpl extends KeyManagerFactorySpi {
   X509ExtendedKeyManager keyManager;
   boolean isInitialized;

   protected KeyManager[] engineGetKeyManagers() {
      if (!this.isInitialized) {
         throw new IllegalStateException("KeyManagerFactoryImpl is not initialized");
      } else {
         return new KeyManager[]{this.keyManager};
      }
   }

   public static final class SunX509 extends KeyManagerFactoryImpl {
      protected void engineInit(KeyStore var1, char[] var2) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
         if (var1 != null && MyJSSE.isFIPS() && var1.getProvider() != MyJSSE.cryptoProvider) {
            throw new KeyStoreException("FIPS mode: KeyStore must be from provider " + MyJSSE.cryptoProvider.getName());
         } else {
            this.keyManager = new SunX509KeyManagerImpl(var1, var2);
            this.isInitialized = true;
         }
      }

      protected void engineInit(ManagerFactoryParameters var1) throws InvalidAlgorithmParameterException {
         throw new InvalidAlgorithmParameterException("SunX509KeyManager does not use ManagerFactoryParameters");
      }
   }

   public static final class X509 extends KeyManagerFactoryImpl {
      protected void engineInit(KeyStore var1, char[] var2) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
         if (var1 == null) {
            this.keyManager = new X509KeyManagerImpl(new ArrayList<Builder>());
         } else {
            if (MyJSSE.isFIPS() && var1.getProvider() != MyJSSE.cryptoProvider) {
               throw new KeyStoreException("FIPS mode: KeyStore must be from provider " + MyJSSE.cryptoProvider.getName());
            }

            try {
               Builder var3 = Builder.newInstance(var1, new PasswordProtection(var2));
               this.keyManager = new X509KeyManagerImpl(var3);
            } catch (RuntimeException var4) {
               throw new KeyStoreException("initialization failed", var4);
            }
         }

         this.isInitialized = true;
      }

      protected void engineInit(ManagerFactoryParameters var1) throws InvalidAlgorithmParameterException {
         if (!(var1 instanceof KeyStoreBuilderParameters)) {
            throw new InvalidAlgorithmParameterException("Parameters must be instance of KeyStoreBuilderParameters");
         } else if (MyJSSE.isFIPS()) {
            throw new InvalidAlgorithmParameterException("FIPS mode: KeyStoreBuilderParameters not supported");
         } else {
            List var2 = ((KeyStoreBuilderParameters)var1).getParameters();
            this.keyManager = new X509KeyManagerImpl(var2);
            this.isInitialized = true;
         }
      }
   }
}
