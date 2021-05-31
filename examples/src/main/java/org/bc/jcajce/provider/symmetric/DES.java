package org.bc.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.oiw.OIWObjectIdentifiers;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.engines.DESEngine;
import org.bc.crypto.engines.RFC3211WrapEngine;
import org.bc.crypto.generators.DESKeyGenerator;
import org.bc.crypto.macs.CBCBlockCipherMac;
import org.bc.crypto.macs.CFBBlockCipherMac;
import org.bc.crypto.macs.CMac;
import org.bc.crypto.modes.CBCBlockCipher;
import org.bc.crypto.paddings.ISO7816d4Padding;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseMac;
import org.bc.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bc.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bc.jcajce.provider.util.AlgorithmProvider;
import org.bc.jce.provider.BouncyCastleProvider;

public final class DES {
   public static class AlgParamGen extends BaseAlgorithmParameterGenerator {
      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DES parameter generation.");
      }

      protected AlgorithmParameters engineGenerateParameters() {
         byte[] var1 = new byte[8];
         if (this.random == null) {
            this.random = new SecureRandom();
         }

         this.random.nextBytes(var1);

         try {
            AlgorithmParameters var2 = AlgorithmParameters.getInstance("DES", BouncyCastleProvider.PROVIDER_NAME);
            var2.init(new IvParameterSpec(var1));
            return var2;
         } catch (Exception var4) {
            throw new RuntimeException(var4.getMessage());
         }
      }
   }

   public static class CBC extends BaseBlockCipher {
      public CBC() {
         super((BlockCipher)(new CBCBlockCipher(new DESEngine())), 64);
      }
   }

   public static class CBCMAC extends BaseMac {
      public CBCMAC() {
         super(new CBCBlockCipherMac(new DESEngine()));
      }
   }

   public static class CMAC extends BaseMac {
      public CMAC() {
         super(new CMac(new DESEngine()));
      }
   }

   public static class DES64 extends BaseMac {
      public DES64() {
         super(new CBCBlockCipherMac(new DESEngine(), 64));
      }
   }

   public static class DES64with7816d4 extends BaseMac {
      public DES64with7816d4() {
         super(new CBCBlockCipherMac(new DESEngine(), 64, new ISO7816d4Padding()));
      }
   }

   public static class DESCFB8 extends BaseMac {
      public DESCFB8() {
         super(new CFBBlockCipherMac(new DESEngine()));
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new DESEngine());
      }
   }

   public static class KeyFactory extends BaseSecretKeyFactory {
      public KeyFactory() {
         super("DES", (ASN1ObjectIdentifier)null);
      }

      protected KeySpec engineGetKeySpec(SecretKey var1, Class var2) throws InvalidKeySpecException {
         if (var2 == null) {
            throw new InvalidKeySpecException("keySpec parameter is null");
         } else if (var1 == null) {
            throw new InvalidKeySpecException("key parameter is null");
         } else if (SecretKeySpec.class.isAssignableFrom(var2)) {
            return new SecretKeySpec(var1.getEncoded(), this.algName);
         } else if (DESKeySpec.class.isAssignableFrom(var2)) {
            byte[] var3 = var1.getEncoded();

            try {
               return new DESKeySpec(var3);
            } catch (Exception var5) {
               throw new InvalidKeySpecException(var5.toString());
            }
         } else {
            throw new InvalidKeySpecException("Invalid KeySpec");
         }
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

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("DES", 64, new DESKeyGenerator());
      }

      protected void engineInit(int var1, SecureRandom var2) {
         super.engineInit(var1, var2);
      }

      protected SecretKey engineGenerateKey() {
         if (this.uninitialised) {
            this.engine.init(new KeyGenerationParameters(new SecureRandom(), this.defaultKeySize));
            this.uninitialised = false;
         }

         return new SecretKeySpec(this.engine.generateKey(), this.algName);
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = DES.class.getName();
      private static final String PACKAGE = "org.bc.jcajce.provider.symmetric";

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.DES", PREFIX + "$ECB");
         var1.addAlgorithm("Cipher." + OIWObjectIdentifiers.desCBC, PREFIX + "$CBC");
         this.addAlias(var1, OIWObjectIdentifiers.desCBC, "DES");
         var1.addAlgorithm("Cipher.DESRFC3211WRAP", PREFIX + "$RFC3211");
         var1.addAlgorithm("KeyGenerator.DES", PREFIX + "$KeyGenerator");
         var1.addAlgorithm("SecretKeyFactory.DES", PREFIX + "$KeyFactory");
         var1.addAlgorithm("Mac.DESCMAC", PREFIX + "$CMAC");
         var1.addAlgorithm("Mac.DESMAC", PREFIX + "$CBCMAC");
         var1.addAlgorithm("Alg.Alias.Mac.DES", "DESMAC");
         var1.addAlgorithm("Mac.DESMAC/CFB8", PREFIX + "$DESCFB8");
         var1.addAlgorithm("Alg.Alias.Mac.DES/CFB8", "DESMAC/CFB8");
         var1.addAlgorithm("Mac.DESMAC64", PREFIX + "$DES64");
         var1.addAlgorithm("Alg.Alias.Mac.DES64", "DESMAC64");
         var1.addAlgorithm("Mac.DESMAC64WITHISO7816-4PADDING", PREFIX + "$DES64with7816d4");
         var1.addAlgorithm("Alg.Alias.Mac.DES64WITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");
         var1.addAlgorithm("Alg.Alias.Mac.DESISO9797ALG1MACWITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");
         var1.addAlgorithm("Alg.Alias.Mac.DESISO9797ALG1WITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");
         var1.addAlgorithm("AlgorithmParameters.DES", "org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters." + OIWObjectIdentifiers.desCBC, "DES");
         var1.addAlgorithm("AlgorithmParameterGenerator.DES", PREFIX + "$AlgParamGen");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + OIWObjectIdentifiers.desCBC, "DES");
      }

      private void addAlias(ConfigurableProvider var1, ASN1ObjectIdentifier var2, String var3) {
         var1.addAlgorithm("Alg.Alias.KeyGenerator." + var2.getId(), var3);
         var1.addAlgorithm("Alg.Alias.KeyFactory." + var2.getId(), var3);
      }
   }

   public static class RFC3211 extends BaseWrapCipher {
      public RFC3211() {
         super(new RFC3211WrapEngine(new DESEngine()), 8);
      }
   }
}
