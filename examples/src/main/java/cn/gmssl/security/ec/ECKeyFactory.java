package cn.gmssl.security.ec;

import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class ECKeyFactory extends KeyFactorySpi {
   public static final KeyFactory INSTANCE;
   public static final Provider ecInternalProvider;

   static {
      final Provider var0 = new Provider("SunEC-Internal", 1.0D, (String)null) {
      };
      AccessController.doPrivileged(new PrivilegedAction<Void>() {
         public Void run() {
            var0.put("KeyFactory.EC", "sun.security.ec.ECKeyFactory");
            var0.put("AlgorithmParameters.EC", "sun.security.ec.ECParameters");
            var0.put("Alg.Alias.AlgorithmParameters.1.2.840.10045.2.1", "EC");
            return null;
         }
      });

      try {
         INSTANCE = KeyFactory.getInstance("EC", var0);
      } catch (NoSuchAlgorithmException var2) {
         throw new RuntimeException(var2);
      }

      ecInternalProvider = var0;
   }

   public static ECKey toECKey(Key var0) throws InvalidKeyException {
      if (var0 instanceof ECKey) {
         ECKey var1 = (ECKey)var0;
         checkKey(var1);
         return var1;
      } else {
         return (ECKey)INSTANCE.translateKey(var0);
      }
   }

   private static void checkKey(ECKey var0) throws InvalidKeyException {
      if (var0 instanceof ECPublicKey) {
         if (var0 instanceof ECPublicKeyImpl) {
            return;
         }
      } else {
         if (!(var0 instanceof ECPrivateKey)) {
            throw new InvalidKeyException("Neither a public nor a private key");
         }

         if (var0 instanceof ECPrivateKeyImpl) {
            return;
         }
      }

      String var1 = ((Key)var0).getAlgorithm();
      if (!var1.equals("EC")) {
         throw new InvalidKeyException("Not an EC key: " + var1);
      }
   }

   protected Key engineTranslateKey(Key var1) throws InvalidKeyException {
      if (var1 == null) {
         throw new InvalidKeyException("Key must not be null");
      } else {
         String var2 = var1.getAlgorithm();
         if (!var2.equals("EC")) {
            throw new InvalidKeyException("Not an EC key: " + var2);
         } else if (var1 instanceof PublicKey) {
            return this.implTranslatePublicKey((PublicKey)var1);
         } else if (var1 instanceof PrivateKey) {
            return this.implTranslatePrivateKey((PrivateKey)var1);
         } else {
            throw new InvalidKeyException("Neither a public nor a private key");
         }
      }
   }

   protected PublicKey engineGeneratePublic(KeySpec var1) throws InvalidKeySpecException {
      try {
         return this.implGeneratePublic(var1);
      } catch (InvalidKeySpecException var3) {
         throw var3;
      } catch (GeneralSecurityException var4) {
         throw new InvalidKeySpecException(var4);
      }
   }

   protected PrivateKey engineGeneratePrivate(KeySpec var1) throws InvalidKeySpecException {
      try {
         return this.implGeneratePrivate(var1);
      } catch (InvalidKeySpecException var3) {
         throw var3;
      } catch (GeneralSecurityException var4) {
         throw new InvalidKeySpecException(var4);
      }
   }

   private PublicKey implTranslatePublicKey(PublicKey var1) throws InvalidKeyException {
      if (var1 instanceof ECPublicKey) {
         if (var1 instanceof ECPublicKeyImpl) {
            return var1;
         } else {
            ECPublicKey var3 = (ECPublicKey)var1;
            return new ECPublicKeyImpl(var3.getW(), var3.getParams());
         }
      } else if ("X.509".equals(var1.getFormat())) {
         byte[] var2 = var1.getEncoded();
         return new ECPublicKeyImpl(var2);
      } else {
         throw new InvalidKeyException("Public keys must be instance of ECPublicKey or have X.509 encoding");
      }
   }

   private PrivateKey implTranslatePrivateKey(PrivateKey var1) throws InvalidKeyException {
      if (var1 instanceof ECPrivateKey) {
         if (var1 instanceof ECPrivateKeyImpl) {
            return var1;
         } else {
            ECPrivateKey var2 = (ECPrivateKey)var1;
            return new ECPrivateKeyImpl(var2.getS(), var2.getParams());
         }
      } else if ("PKCS#8".equals(var1.getFormat())) {
         return new ECPrivateKeyImpl(var1.getEncoded());
      } else {
         throw new InvalidKeyException("Private keys must be instance of ECPrivateKey or have PKCS#8 encoding");
      }
   }

   private PublicKey implGeneratePublic(KeySpec var1) throws GeneralSecurityException {
      if (var1 instanceof X509EncodedKeySpec) {
         X509EncodedKeySpec var3 = (X509EncodedKeySpec)var1;
         return new ECPublicKeyImpl(var3.getEncoded());
      } else if (var1 instanceof ECPublicKeySpec) {
         ECPublicKeySpec var2 = (ECPublicKeySpec)var1;
         return new ECPublicKeyImpl(var2.getW(), var2.getParams());
      } else {
         throw new InvalidKeySpecException("Only ECPublicKeySpec and X509EncodedKeySpec supported for EC public keys");
      }
   }

   private PrivateKey implGeneratePrivate(KeySpec var1) throws GeneralSecurityException {
      if (var1 instanceof PKCS8EncodedKeySpec) {
         PKCS8EncodedKeySpec var3 = (PKCS8EncodedKeySpec)var1;
         return new ECPrivateKeyImpl(var3.getEncoded());
      } else if (var1 instanceof ECPrivateKeySpec) {
         ECPrivateKeySpec var2 = (ECPrivateKeySpec)var1;
         return new ECPrivateKeyImpl(var2.getS(), var2.getParams());
      } else {
         throw new InvalidKeySpecException("Only ECPrivateKeySpec and PKCS8EncodedKeySpec supported for EC private keys");
      }
   }

   protected <T extends KeySpec> T engineGetKeySpec(Key var1, Class<T> var2) throws InvalidKeySpecException {
      try {
         var1 = this.engineTranslateKey(var1);
      } catch (InvalidKeyException var4) {
         throw new InvalidKeySpecException(var4);
      }

      if (var1 instanceof ECPublicKey) {
         ECPublicKey var5 = (ECPublicKey)var1;
         if (ECPublicKeySpec.class.isAssignableFrom(var2)) {
            return (T) new ECPublicKeySpec(var5.getW(), var5.getParams());
         } else if (X509EncodedKeySpec.class.isAssignableFrom(var2)) {
            return (T) new X509EncodedKeySpec(var1.getEncoded());
         } else {
            throw new InvalidKeySpecException("KeySpec must be ECPublicKeySpec or X509EncodedKeySpec for EC public keys");
         }
      } else if (var1 instanceof ECPrivateKey) {
         if (PKCS8EncodedKeySpec.class.isAssignableFrom(var2)) {
            return (T) new PKCS8EncodedKeySpec(var1.getEncoded());
         } else if (ECPrivateKeySpec.class.isAssignableFrom(var2)) {
            ECPrivateKey var3 = (ECPrivateKey)var1;
            return (T) new ECPrivateKeySpec(var3.getS(), var3.getParams());
         } else {
            throw new InvalidKeySpecException("KeySpec must be ECPrivateKeySpec or PKCS8EncodedKeySpec for EC private keys");
         }
      } else {
         throw new InvalidKeySpecException("Neither public nor private key");
      }
   }
}
