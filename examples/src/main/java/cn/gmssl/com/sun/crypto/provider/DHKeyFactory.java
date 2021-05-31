package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

public final class DHKeyFactory extends KeyFactorySpi {
   protected PublicKey engineGeneratePublic(KeySpec var1) throws InvalidKeySpecException {
      try {
         if (var1 instanceof DHPublicKeySpec) {
            DHPublicKeySpec var2 = (DHPublicKeySpec)var1;
            return new DHPublicKey(var2.getY(), var2.getP(), var2.getG());
         } else if (var1 instanceof X509EncodedKeySpec) {
            return new DHPublicKey(((X509EncodedKeySpec)var1).getEncoded());
         } else {
            throw new InvalidKeySpecException("Inappropriate key specification");
         }
      } catch (InvalidKeyException var3) {
         throw new InvalidKeySpecException("Inappropriate key specification");
      }
   }

   protected PrivateKey engineGeneratePrivate(KeySpec var1) throws InvalidKeySpecException {
      try {
         if (var1 instanceof DHPrivateKeySpec) {
            DHPrivateKeySpec var2 = (DHPrivateKeySpec)var1;
            return new DHPrivateKey(var2.getX(), var2.getP(), var2.getG());
         } else if (var1 instanceof PKCS8EncodedKeySpec) {
            return new DHPrivateKey(((PKCS8EncodedKeySpec)var1).getEncoded());
         } else {
            throw new InvalidKeySpecException("Inappropriate key specification");
         }
      } catch (InvalidKeyException var3) {
         throw new InvalidKeySpecException("Inappropriate key specification");
      }
   }

   protected KeySpec engineGetKeySpec(Key var1, Class var2) throws InvalidKeySpecException {
      DHParameterSpec var3;
      if (var1 instanceof javax.crypto.interfaces.DHPublicKey) {
         if (DHPublicKeySpec.class.isAssignableFrom(var2)) {
            javax.crypto.interfaces.DHPublicKey var5 = (javax.crypto.interfaces.DHPublicKey)var1;
            var3 = var5.getParams();
            return new DHPublicKeySpec(var5.getY(), var3.getP(), var3.getG());
         } else if (X509EncodedKeySpec.class.isAssignableFrom(var2)) {
            return new X509EncodedKeySpec(var1.getEncoded());
         } else {
            throw new InvalidKeySpecException("Inappropriate key specification");
         }
      } else if (var1 instanceof javax.crypto.interfaces.DHPrivateKey) {
         if (DHPrivateKeySpec.class.isAssignableFrom(var2)) {
            javax.crypto.interfaces.DHPrivateKey var4 = (javax.crypto.interfaces.DHPrivateKey)var1;
            var3 = var4.getParams();
            return new DHPrivateKeySpec(var4.getX(), var3.getP(), var3.getG());
         } else if (PKCS8EncodedKeySpec.class.isAssignableFrom(var2)) {
            return new PKCS8EncodedKeySpec(var1.getEncoded());
         } else {
            throw new InvalidKeySpecException("Inappropriate key specification");
         }
      } else {
         throw new InvalidKeySpecException("Inappropriate key type");
      }
   }

   protected Key engineTranslateKey(Key var1) throws InvalidKeyException {
      try {
         if (var1 instanceof javax.crypto.interfaces.DHPublicKey) {
            if (var1 instanceof DHPublicKey) {
               return var1;
            } else {
               DHPublicKeySpec var4 = (DHPublicKeySpec)this.engineGetKeySpec(var1, DHPublicKeySpec.class);
               return this.engineGeneratePublic(var4);
            }
         } else if (var1 instanceof javax.crypto.interfaces.DHPrivateKey) {
            if (var1 instanceof DHPrivateKey) {
               return var1;
            } else {
               DHPrivateKeySpec var2 = (DHPrivateKeySpec)this.engineGetKeySpec(var1, DHPrivateKeySpec.class);
               return this.engineGeneratePrivate(var2);
            }
         } else {
            throw new InvalidKeyException("Wrong algorithm type");
         }
      } catch (InvalidKeySpecException var3) {
         throw new InvalidKeyException("Cannot translate key");
      }
   }
}
