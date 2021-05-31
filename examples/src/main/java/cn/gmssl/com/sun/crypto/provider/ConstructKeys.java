package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

final class ConstructKeys {
   private static final PublicKey constructPublicKey(byte[] var0, String var1) throws InvalidKeyException, NoSuchAlgorithmException {
      PublicKey var2 = null;

      try {
         KeyFactory var3 = KeyFactory.getInstance(var1, "SunJCE");
         X509EncodedKeySpec var12 = new X509EncodedKeySpec(var0);
         var2 = var3.generatePublic(var12);
      } catch (NoSuchAlgorithmException var8) {
         try {
            KeyFactory var11 = KeyFactory.getInstance(var1);
            X509EncodedKeySpec var13 = new X509EncodedKeySpec(var0);
            var2 = var11.generatePublic(var13);
         } catch (NoSuchAlgorithmException var6) {
            throw new NoSuchAlgorithmException("No installed providers can create keys for the " + var1 + "algorithm");
         } catch (InvalidKeySpecException var7) {
            InvalidKeyException var5 = new InvalidKeyException("Cannot construct public key");
            var5.initCause(var7);
            throw var5;
         }
      } catch (InvalidKeySpecException var9) {
         InvalidKeyException var4 = new InvalidKeyException("Cannot construct public key");
         var4.initCause(var9);
         throw var4;
      } catch (NoSuchProviderException var10) {
         ;
      }

      return var2;
   }

   private static final PrivateKey constructPrivateKey(byte[] var0, String var1) throws InvalidKeyException, NoSuchAlgorithmException {
      PrivateKey var2 = null;

      try {
         KeyFactory var3 = KeyFactory.getInstance(var1, "SunJCE");
         PKCS8EncodedKeySpec var12 = new PKCS8EncodedKeySpec(var0);
         return var3.generatePrivate(var12);
      } catch (NoSuchAlgorithmException var8) {
         try {
            KeyFactory var11 = KeyFactory.getInstance(var1);
            PKCS8EncodedKeySpec var13 = new PKCS8EncodedKeySpec(var0);
            var2 = var11.generatePrivate(var13);
         } catch (NoSuchAlgorithmException var6) {
            throw new NoSuchAlgorithmException("No installed providers can create keys for the " + var1 + "algorithm");
         } catch (InvalidKeySpecException var7) {
            InvalidKeyException var5 = new InvalidKeyException("Cannot construct private key");
            var5.initCause(var7);
            throw var5;
         }
      } catch (InvalidKeySpecException var9) {
         InvalidKeyException var4 = new InvalidKeyException("Cannot construct private key");
         var4.initCause(var9);
         throw var4;
      } catch (NoSuchProviderException var10) {
         ;
      }

      return var2;
   }

   private static final SecretKey constructSecretKey(byte[] var0, String var1) {
      return new SecretKeySpec(var0, var1);
   }

   static final Key constructKey(byte[] var0, String var1, int var2) throws InvalidKeyException, NoSuchAlgorithmException {
      Object var3 = null;
      switch(var2) {
      case 1:
         var3 = constructPublicKey(var0, var1);
         break;
      case 2:
         var3 = constructPrivateKey(var0, var1);
         break;
      case 3:
         var3 = constructSecretKey(var0, var1);
      }

      return (Key)var3;
   }
}
