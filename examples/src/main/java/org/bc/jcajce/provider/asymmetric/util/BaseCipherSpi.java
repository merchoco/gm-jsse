package org.bc.jcajce.provider.asymmetric.util;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.Wrapper;
import org.bc.jce.provider.BouncyCastleProvider;

public abstract class BaseCipherSpi extends CipherSpi {
   private Class[] availableSpecs = new Class[]{IvParameterSpec.class, PBEParameterSpec.class, RC2ParameterSpec.class, RC5ParameterSpec.class};
   protected AlgorithmParameters engineParams = null;
   protected Wrapper wrapEngine = null;
   private int ivSize;
   private byte[] iv;

   protected int engineGetBlockSize() {
      return 0;
   }

   protected byte[] engineGetIV() {
      return null;
   }

   protected int engineGetKeySize(Key var1) {
      return var1.getEncoded().length;
   }

   protected int engineGetOutputSize(int var1) {
      return -1;
   }

   protected AlgorithmParameters engineGetParameters() {
      return null;
   }

   protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
      throw new NoSuchAlgorithmException("can't support mode " + var1);
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      throw new NoSuchPaddingException("Padding " + var1 + " unknown.");
   }

   protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      byte[] var2 = var1.getEncoded();
      if (var2 == null) {
         throw new InvalidKeyException("Cannot wrap key, null encoding.");
      } else {
         try {
            return this.wrapEngine == null ? this.engineDoFinal(var2, 0, var2.length) : this.wrapEngine.wrap(var2, 0, var2.length);
         } catch (BadPaddingException var4) {
            throw new IllegalBlockSizeException(var4.getMessage());
         }
      }
   }

   protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException {
      byte[] var4;
      try {
         if (this.wrapEngine == null) {
            var4 = this.engineDoFinal(var1, 0, var1.length);
         } else {
            var4 = this.wrapEngine.unwrap(var1, 0, var1.length);
         }
      } catch (InvalidCipherTextException var8) {
         throw new InvalidKeyException(var8.getMessage());
      } catch (BadPaddingException var9) {
         throw new InvalidKeyException(var9.getMessage());
      } catch (IllegalBlockSizeException var10) {
         throw new InvalidKeyException(var10.getMessage());
      }

      if (var3 == 3) {
         return new SecretKeySpec(var4, var2);
      } else if (var2.equals("") && var3 == 2) {
         try {
            PrivateKeyInfo var14 = PrivateKeyInfo.getInstance(var4);
            PrivateKey var6 = BouncyCastleProvider.getPrivateKey(var14);
            if (var6 != null) {
               return var6;
            } else {
               throw new InvalidKeyException("algorithm " + var14.getPrivateKeyAlgorithm().getAlgorithm() + " not supported");
            }
         } catch (Exception var7) {
            var7.printStackTrace();
            throw new InvalidKeyException("Invalid key encoding.");
         }
      } else {
         try {
            KeyFactory var5 = KeyFactory.getInstance(var2, BouncyCastleProvider.PROVIDER_NAME);
            if (var3 == 1) {
               return var5.generatePublic(new X509EncodedKeySpec(var4));
            }

            if (var3 == 2) {
               return var5.generatePrivate(new PKCS8EncodedKeySpec(var4));
            }
         } catch (NoSuchProviderException var11) {
            throw new InvalidKeyException("Unknown key type " + var11.getMessage());
         } catch (NoSuchAlgorithmException var12) {
            throw new InvalidKeyException("Unknown key type " + var12.getMessage());
         } catch (InvalidKeySpecException var13) {
            throw new InvalidKeyException("Unknown key type " + var13.getMessage());
         }

         throw new InvalidKeyException("Unknown key type " + var3);
      }
   }
}
