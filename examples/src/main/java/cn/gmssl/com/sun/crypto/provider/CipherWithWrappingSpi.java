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
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public abstract class CipherWithWrappingSpi extends CipherSpi {
   protected final byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      byte[] var2 = null;

      try {
         byte[] var3 = var1.getEncoded();
         if (var3 == null || var3.length == 0) {
            throw new InvalidKeyException("Cannot get an encoding of the key to be wrapped");
         }

         var2 = this.engineDoFinal(var3, 0, var3.length);
      } catch (BadPaddingException var4) {
         ;
      }

      return var2;
   }

   protected final Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      Object var5 = null;

      byte[] var4;
      try {
         var4 = this.engineDoFinal(var1, 0, var1.length);
      } catch (BadPaddingException var7) {
         throw new InvalidKeyException();
      } catch (IllegalBlockSizeException var8) {
         throw new InvalidKeyException();
      }

      switch(var3) {
      case 1:
         var5 = this.constructPublicKey(var4, var2);
         break;
      case 2:
         var5 = this.constructPrivateKey(var4, var2);
         break;
      case 3:
         var5 = this.constructSecretKey(var4, var2);
      }

      return (Key)var5;
   }

   private final PublicKey constructPublicKey(byte[] var1, String var2) throws InvalidKeyException, NoSuchAlgorithmException {
      PublicKey var3 = null;

      try {
         KeyFactory var4 = KeyFactory.getInstance(var2, "SunJCE");
         X509EncodedKeySpec var12 = new X509EncodedKeySpec(var1);
         var3 = var4.generatePublic(var12);
      } catch (NoSuchAlgorithmException var9) {
         try {
            KeyFactory var5 = KeyFactory.getInstance(var2);
            X509EncodedKeySpec var6 = new X509EncodedKeySpec(var1);
            var3 = var5.generatePublic(var6);
         } catch (NoSuchAlgorithmException var7) {
            throw new NoSuchAlgorithmException("No installed providers can create keys for the " + var2 + "algorithm");
         } catch (InvalidKeySpecException var8) {
            ;
         }
      } catch (InvalidKeySpecException var10) {
         ;
      } catch (NoSuchProviderException var11) {
         ;
      }

      return var3;
   }

   private final PrivateKey constructPrivateKey(byte[] var1, String var2) throws InvalidKeyException, NoSuchAlgorithmException {
      PrivateKey var3 = null;

      try {
         KeyFactory var4 = KeyFactory.getInstance(var2, "SunJCE");
         PKCS8EncodedKeySpec var12 = new PKCS8EncodedKeySpec(var1);
         return var4.generatePrivate(var12);
      } catch (NoSuchAlgorithmException var9) {
         try {
            KeyFactory var5 = KeyFactory.getInstance(var2);
            PKCS8EncodedKeySpec var6 = new PKCS8EncodedKeySpec(var1);
            var3 = var5.generatePrivate(var6);
         } catch (NoSuchAlgorithmException var7) {
            throw new NoSuchAlgorithmException("No installed providers can create keys for the " + var2 + "algorithm");
         } catch (InvalidKeySpecException var8) {
            ;
         }
      } catch (InvalidKeySpecException var10) {
         ;
      } catch (NoSuchProviderException var11) {
         ;
      }

      return var3;
   }

   private final SecretKey constructSecretKey(byte[] var1, String var2) {
      return new SecretKeySpec(var1, var2);
   }
}
