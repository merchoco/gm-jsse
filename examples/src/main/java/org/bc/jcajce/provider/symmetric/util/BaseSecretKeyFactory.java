package org.bc.jcajce.provider.symmetric.util;

import java.lang.reflect.Constructor;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.params.DESParameters;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;

public class BaseSecretKeyFactory extends SecretKeyFactorySpi implements PBE {
   protected String algName;
   protected ASN1ObjectIdentifier algOid;

   protected BaseSecretKeyFactory(String var1, ASN1ObjectIdentifier var2) {
      this.algName = var1;
      this.algOid = var2;
   }

   protected SecretKey engineGenerateSecret(KeySpec var1) throws InvalidKeySpecException {
      if (var1 instanceof SecretKeySpec) {
         return (SecretKey)var1;
      } else {
         throw new InvalidKeySpecException("Invalid KeySpec");
      }
   }

   protected KeySpec engineGetKeySpec(SecretKey var1, Class var2) throws InvalidKeySpecException {
      if (var2 == null) {
         throw new InvalidKeySpecException("keySpec parameter is null");
      } else if (var1 == null) {
         throw new InvalidKeySpecException("key parameter is null");
      } else if (SecretKeySpec.class.isAssignableFrom(var2)) {
         return new SecretKeySpec(var1.getEncoded(), this.algName);
      } else {
         try {
            Class[] var3 = new Class[]{byte[].class};
            Constructor var4 = var2.getConstructor(var3);
            Object[] var5 = new Object[]{var1.getEncoded()};
            return (KeySpec)var4.newInstance(var5);
         } catch (Exception var6) {
            throw new InvalidKeySpecException(var6.toString());
         }
      }
   }

   protected SecretKey engineTranslateKey(SecretKey var1) throws InvalidKeyException {
      if (var1 == null) {
         throw new InvalidKeyException("key parameter is null");
      } else if (!var1.getAlgorithm().equalsIgnoreCase(this.algName)) {
         throw new InvalidKeyException("Key not of type " + this.algName + ".");
      } else {
         return new SecretKeySpec(var1.getEncoded(), this.algName);
      }
   }

   public static class DES extends BaseSecretKeyFactory {
      public DES() {
         super("DES", (ASN1ObjectIdentifier)null);
      }

      protected SecretKey engineGenerateSecret(KeySpec var1) throws InvalidKeySpecException {
         if (var1 instanceof DESKeySpec) {
            DESKeySpec var2 = (DESKeySpec)var1;
            return new SecretKeySpec(var2.getKey(), "DES");
         } else {
            return super.engineGenerateSecret(var1);
         }
      }
   }

   public static class DESPBEKeyFactory extends BaseSecretKeyFactory {
      private boolean forCipher;
      private int scheme;
      private int digest;
      private int keySize;
      private int ivSize;

      public DESPBEKeyFactory(String var1, ASN1ObjectIdentifier var2, boolean var3, int var4, int var5, int var6, int var7) {
         super(var1, var2);
         this.forCipher = var3;
         this.scheme = var4;
         this.digest = var5;
         this.keySize = var6;
         this.ivSize = var7;
      }

      protected SecretKey engineGenerateSecret(KeySpec var1) throws InvalidKeySpecException {
         if (var1 instanceof PBEKeySpec) {
            PBEKeySpec var2 = (PBEKeySpec)var1;
            if (var2.getSalt() == null) {
               return new BCPBEKey(this.algName, this.algOid, this.scheme, this.digest, this.keySize, this.ivSize, var2, (CipherParameters)null);
            } else {
               CipherParameters var3;
               if (this.forCipher) {
                  var3 = PBE.Util.makePBEParameters(var2, this.scheme, this.digest, this.keySize, this.ivSize);
               } else {
                  var3 = PBE.Util.makePBEMacParameters(var2, this.scheme, this.digest, this.keySize);
               }

               KeyParameter var4;
               if (var3 instanceof ParametersWithIV) {
                  var4 = (KeyParameter)((ParametersWithIV)var3).getParameters();
               } else {
                  var4 = (KeyParameter)var3;
               }

               DESParameters.setOddParity(var4.getKey());
               return new BCPBEKey(this.algName, this.algOid, this.scheme, this.digest, this.keySize, this.ivSize, var2, var3);
            }
         } else {
            throw new InvalidKeySpecException("Invalid KeySpec");
         }
      }
   }
}
