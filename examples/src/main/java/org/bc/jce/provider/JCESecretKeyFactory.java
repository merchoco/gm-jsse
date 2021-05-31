package org.bc.jce.provider;

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
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.params.DESParameters;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;
import org.bc.jcajce.provider.symmetric.util.BCPBEKey;
import org.bc.jcajce.provider.symmetric.util.PBE;

public class JCESecretKeyFactory extends SecretKeyFactorySpi implements PBE {
   protected String algName;
   protected ASN1ObjectIdentifier algOid;

   protected JCESecretKeyFactory(String var1, ASN1ObjectIdentifier var2) {
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

   public static class DES extends JCESecretKeyFactory {
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

   public static class DESPBEKeyFactory extends JCESecretKeyFactory {
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

   public static class PBEKeyFactory extends JCESecretKeyFactory {
      private boolean forCipher;
      private int scheme;
      private int digest;
      private int keySize;
      private int ivSize;

      public PBEKeyFactory(String var1, ASN1ObjectIdentifier var2, boolean var3, int var4, int var5, int var6, int var7) {
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

               return new BCPBEKey(this.algName, this.algOid, this.scheme, this.digest, this.keySize, this.ivSize, var2, var3);
            }
         } else {
            throw new InvalidKeySpecException("Invalid KeySpec");
         }
      }
   }

   public static class PBEWithMD2AndDES extends JCESecretKeyFactory.DESPBEKeyFactory {
      public PBEWithMD2AndDES() {
         super("PBEwithMD2andDES", PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, true, 0, 5, 64, 64);
      }
   }

   public static class PBEWithMD2AndRC2 extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithMD2AndRC2() {
         super("PBEwithMD2andRC2", PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC, true, 0, 5, 64, 64);
      }
   }

   public static class PBEWithMD5And128BitAESCBCOpenSSL extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithMD5And128BitAESCBCOpenSSL() {
         super("PBEWithMD5And128BitAES-CBC-OpenSSL", (ASN1ObjectIdentifier)null, true, 3, 0, 128, 128);
      }
   }

   public static class PBEWithMD5And192BitAESCBCOpenSSL extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithMD5And192BitAESCBCOpenSSL() {
         super("PBEWithMD5And192BitAES-CBC-OpenSSL", (ASN1ObjectIdentifier)null, true, 3, 0, 192, 128);
      }
   }

   public static class PBEWithMD5And256BitAESCBCOpenSSL extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithMD5And256BitAESCBCOpenSSL() {
         super("PBEWithMD5And256BitAES-CBC-OpenSSL", (ASN1ObjectIdentifier)null, true, 3, 0, 256, 128);
      }
   }

   public static class PBEWithMD5AndDES extends JCESecretKeyFactory.DESPBEKeyFactory {
      public PBEWithMD5AndDES() {
         super("PBEwithMD5andDES", PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, true, 0, 0, 64, 64);
      }
   }

   public static class PBEWithMD5AndRC2 extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithMD5AndRC2() {
         super("PBEwithMD5andRC2", PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC, true, 0, 0, 64, 64);
      }
   }

   public static class PBEWithRIPEMD160 extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithRIPEMD160() {
         super("PBEwithHmacRIPEMD160", (ASN1ObjectIdentifier)null, false, 2, 2, 160, 0);
      }
   }

   public static class PBEWithSHA extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHA() {
         super("PBEwithHmacSHA", (ASN1ObjectIdentifier)null, false, 2, 1, 160, 0);
      }
   }

   public static class PBEWithSHA1AndDES extends JCESecretKeyFactory.DESPBEKeyFactory {
      public PBEWithSHA1AndDES() {
         super("PBEwithSHA1andDES", PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, true, 0, 1, 64, 64);
      }
   }

   public static class PBEWithSHA1AndRC2 extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHA1AndRC2() {
         super("PBEwithSHA1andRC2", PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC, true, 0, 1, 64, 64);
      }
   }

   public static class PBEWithSHA256And128BitAESBC extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHA256And128BitAESBC() {
         super("PBEWithSHA256And128BitAES-CBC-BC", (ASN1ObjectIdentifier)null, true, 2, 4, 128, 128);
      }
   }

   public static class PBEWithSHA256And192BitAESBC extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHA256And192BitAESBC() {
         super("PBEWithSHA256And192BitAES-CBC-BC", (ASN1ObjectIdentifier)null, true, 2, 4, 192, 128);
      }
   }

   public static class PBEWithSHA256And256BitAESBC extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHA256And256BitAESBC() {
         super("PBEWithSHA256And256BitAES-CBC-BC", (ASN1ObjectIdentifier)null, true, 2, 4, 256, 128);
      }
   }

   public static class PBEWithSHAAnd128BitAESBC extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHAAnd128BitAESBC() {
         super("PBEWithSHA1And128BitAES-CBC-BC", (ASN1ObjectIdentifier)null, true, 2, 1, 128, 128);
      }
   }

   public static class PBEWithSHAAnd128BitRC2 extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHAAnd128BitRC2() {
         super("PBEwithSHAand128BitRC2-CBC", PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC, true, 2, 1, 128, 64);
      }
   }

   public static class PBEWithSHAAnd128BitRC4 extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHAAnd128BitRC4() {
         super("PBEWithSHAAnd128BitRC4", PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4, true, 2, 1, 128, 0);
      }
   }

   public static class PBEWithSHAAnd192BitAESBC extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHAAnd192BitAESBC() {
         super("PBEWithSHA1And192BitAES-CBC-BC", (ASN1ObjectIdentifier)null, true, 2, 1, 192, 128);
      }
   }

   public static class PBEWithSHAAnd256BitAESBC extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHAAnd256BitAESBC() {
         super("PBEWithSHA1And256BitAES-CBC-BC", (ASN1ObjectIdentifier)null, true, 2, 1, 256, 128);
      }
   }

   public static class PBEWithSHAAnd40BitRC2 extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHAAnd40BitRC2() {
         super("PBEwithSHAand40BitRC2-CBC", PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, true, 2, 1, 40, 64);
      }
   }

   public static class PBEWithSHAAnd40BitRC4 extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHAAnd40BitRC4() {
         super("PBEWithSHAAnd128BitRC4", PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4, true, 2, 1, 40, 0);
      }
   }

   public static class PBEWithSHAAndDES2Key extends JCESecretKeyFactory.DESPBEKeyFactory {
      public PBEWithSHAAndDES2Key() {
         super("PBEwithSHAandDES2Key-CBC", PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC, true, 2, 1, 128, 64);
      }
   }

   public static class PBEWithSHAAndDES3Key extends JCESecretKeyFactory.DESPBEKeyFactory {
      public PBEWithSHAAndDES3Key() {
         super("PBEwithSHAandDES3Key-CBC", PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, true, 2, 1, 192, 64);
      }
   }

   public static class PBEWithSHAAndTwofish extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithSHAAndTwofish() {
         super("PBEwithSHAandTwofish-CBC", (ASN1ObjectIdentifier)null, true, 2, 1, 256, 128);
      }
   }

   public static class PBEWithTiger extends JCESecretKeyFactory.PBEKeyFactory {
      public PBEWithTiger() {
         super("PBEwithHmacTiger", (ASN1ObjectIdentifier)null, false, 2, 3, 192, 0);
      }
   }
}
