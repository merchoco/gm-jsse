package org.bc.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.BufferedBlockCipher;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.AESFastEngine;
import org.bc.crypto.engines.AESWrapEngine;
import org.bc.crypto.engines.RFC3211WrapEngine;
import org.bc.crypto.macs.CMac;
import org.bc.crypto.modes.CBCBlockCipher;
import org.bc.crypto.modes.CFBBlockCipher;
import org.bc.crypto.modes.OFBBlockCipher;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseMac;
import org.bc.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bc.jcajce.provider.util.AlgorithmProvider;
import org.bc.jce.provider.BouncyCastleProvider;

public final class AES {
   public static class AESCMAC extends BaseMac {
      public AESCMAC() {
         super(new CMac(new AESFastEngine()));
      }
   }

   public static class AlgParamGen extends BaseAlgorithmParameterGenerator {
      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for AES parameter generation.");
      }

      protected AlgorithmParameters engineGenerateParameters() {
         byte[] var1 = new byte[16];
         if (this.random == null) {
            this.random = new SecureRandom();
         }

         this.random.nextBytes(var1);

         try {
            AlgorithmParameters var2 = AlgorithmParameters.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
            var2.init(new IvParameterSpec(var1));
            return var2;
         } catch (Exception var4) {
            throw new RuntimeException(var4.getMessage());
         }
      }
   }

   public static class AlgParams extends IvAlgorithmParameters {
      protected String engineToString() {
         return "AES IV";
      }
   }

   public static class CBC extends BaseBlockCipher {
      public CBC() {
         super((BlockCipher)(new CBCBlockCipher(new AESFastEngine())), 128);
      }
   }

   public static class CFB extends BaseBlockCipher {
      public CFB() {
         super((BufferedBlockCipher)(new BufferedBlockCipher(new CFBBlockCipher(new AESFastEngine(), 128))), 128);
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new AESFastEngine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         this(192);
      }

      public KeyGen(int var1) {
         super("AES", var1, new CipherKeyGenerator());
      }
   }

   public static class KeyGen128 extends AES.KeyGen {
      public KeyGen128() {
         super(128);
      }
   }

   public static class KeyGen192 extends AES.KeyGen {
      public KeyGen192() {
         super(192);
      }
   }

   public static class KeyGen256 extends AES.KeyGen {
      public KeyGen256() {
         super(256);
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = AES.class.getName();
      private static final String wrongAES128 = "2.16.840.1.101.3.4.2";
      private static final String wrongAES192 = "2.16.840.1.101.3.4.22";
      private static final String wrongAES256 = "2.16.840.1.101.3.4.42";

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("AlgorithmParameters.AES", PREFIX + "$AlgParams");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.2.16.840.1.101.3.4.2", "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.2.16.840.1.101.3.4.22", "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.2.16.840.1.101.3.4.42", "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes128_CBC, "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes192_CBC, "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes256_CBC, "AES");
         var1.addAlgorithm("AlgorithmParameterGenerator.AES", PREFIX + "$AlgParamGen");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.2.16.840.1.101.3.4.2", "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.2.16.840.1.101.3.4.22", "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.2.16.840.1.101.3.4.42", "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes128_CBC, "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes192_CBC, "AES");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes256_CBC, "AES");
         var1.addAlgorithm("Cipher.AES", PREFIX + "$ECB");
         var1.addAlgorithm("Alg.Alias.Cipher.2.16.840.1.101.3.4.2", "AES");
         var1.addAlgorithm("Alg.Alias.Cipher.2.16.840.1.101.3.4.22", "AES");
         var1.addAlgorithm("Alg.Alias.Cipher.2.16.840.1.101.3.4.42", "AES");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes128_ECB, PREFIX + "$ECB");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes192_ECB, PREFIX + "$ECB");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes256_ECB, PREFIX + "$ECB");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "$CBC");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "$CBC");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "$CBC");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes128_OFB, PREFIX + "$OFB");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes192_OFB, PREFIX + "$OFB");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes256_OFB, PREFIX + "$OFB");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes128_CFB, PREFIX + "$CFB");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes192_CFB, PREFIX + "$CFB");
         var1.addAlgorithm("Cipher." + NISTObjectIdentifiers.id_aes256_CFB, PREFIX + "$CFB");
         var1.addAlgorithm("Cipher.AESWRAP", PREFIX + "$Wrap");
         var1.addAlgorithm("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes128_wrap, "AESWRAP");
         var1.addAlgorithm("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes192_wrap, "AESWRAP");
         var1.addAlgorithm("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes256_wrap, "AESWRAP");
         var1.addAlgorithm("Cipher.AESRFC3211WRAP", PREFIX + "$RFC3211Wrap");
         var1.addAlgorithm("KeyGenerator.AES", PREFIX + "$KeyGen");
         var1.addAlgorithm("KeyGenerator.2.16.840.1.101.3.4.2", PREFIX + "$KeyGen128");
         var1.addAlgorithm("KeyGenerator.2.16.840.1.101.3.4.22", PREFIX + "$KeyGen192");
         var1.addAlgorithm("KeyGenerator.2.16.840.1.101.3.4.42", PREFIX + "$KeyGen256");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes128_ECB, PREFIX + "$KeyGen128");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "$KeyGen128");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes128_OFB, PREFIX + "$KeyGen128");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes128_CFB, PREFIX + "$KeyGen128");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes192_ECB, PREFIX + "$KeyGen192");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "$KeyGen192");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes192_OFB, PREFIX + "$KeyGen192");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes192_CFB, PREFIX + "$KeyGen192");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes256_ECB, PREFIX + "$KeyGen256");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "$KeyGen256");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes256_OFB, PREFIX + "$KeyGen256");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes256_CFB, PREFIX + "$KeyGen256");
         var1.addAlgorithm("KeyGenerator.AESWRAP", PREFIX + "$KeyGen");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes128_wrap, PREFIX + "$KeyGen128");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes192_wrap, PREFIX + "$KeyGen192");
         var1.addAlgorithm("KeyGenerator." + NISTObjectIdentifiers.id_aes256_wrap, PREFIX + "$KeyGen256");
         var1.addAlgorithm("Mac.AESCMAC", PREFIX + "$AESCMAC");
      }
   }

   public static class OFB extends BaseBlockCipher {
      public OFB() {
         super((BufferedBlockCipher)(new BufferedBlockCipher(new OFBBlockCipher(new AESFastEngine(), 128))), 128);
      }
   }

   public static class RFC3211Wrap extends BaseWrapCipher {
      public RFC3211Wrap() {
         super(new RFC3211WrapEngine(new AESFastEngine()), 16);
      }
   }

   public static class Wrap extends BaseWrapCipher {
      public Wrap() {
         super(new AESWrapEngine());
      }
   }
}
