package org.bc.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.bc.asn1.ntt.NTTObjectIdentifiers;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.CamelliaEngine;
import org.bc.crypto.engines.CamelliaWrapEngine;
import org.bc.crypto.engines.RFC3211WrapEngine;
import org.bc.crypto.modes.CBCBlockCipher;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bc.jcajce.provider.util.AlgorithmProvider;
import org.bc.jce.provider.BouncyCastleProvider;

public final class Camellia {
   public static class AlgParamGen extends BaseAlgorithmParameterGenerator {
      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for Camellia parameter generation.");
      }

      protected AlgorithmParameters engineGenerateParameters() {
         byte[] var1 = new byte[16];
         if (this.random == null) {
            this.random = new SecureRandom();
         }

         this.random.nextBytes(var1);

         try {
            AlgorithmParameters var2 = AlgorithmParameters.getInstance("Camellia", BouncyCastleProvider.PROVIDER_NAME);
            var2.init(new IvParameterSpec(var1));
            return var2;
         } catch (Exception var4) {
            throw new RuntimeException(var4.getMessage());
         }
      }
   }

   public static class AlgParams extends IvAlgorithmParameters {
      protected String engineToString() {
         return "Camellia IV";
      }
   }

   public static class CBC extends BaseBlockCipher {
      public CBC() {
         super((BlockCipher)(new CBCBlockCipher(new CamelliaEngine())), 128);
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new CamelliaEngine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         this(256);
      }

      public KeyGen(int var1) {
         super("Camellia", var1, new CipherKeyGenerator());
      }
   }

   public static class KeyGen128 extends Camellia.KeyGen {
      public KeyGen128() {
         super(128);
      }
   }

   public static class KeyGen192 extends Camellia.KeyGen {
      public KeyGen192() {
         super(192);
      }
   }

   public static class KeyGen256 extends Camellia.KeyGen {
      public KeyGen256() {
         super(256);
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = Camellia.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("AlgorithmParameters.CAMELLIA", PREFIX + "$AlgParams");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters." + NTTObjectIdentifiers.id_camellia128_cbc, "CAMELLIA");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters." + NTTObjectIdentifiers.id_camellia192_cbc, "CAMELLIA");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters." + NTTObjectIdentifiers.id_camellia256_cbc, "CAMELLIA");
         var1.addAlgorithm("AlgorithmParameterGenerator.CAMELLIA", PREFIX + "$AlgParamGen");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NTTObjectIdentifiers.id_camellia128_cbc, "CAMELLIA");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NTTObjectIdentifiers.id_camellia192_cbc, "CAMELLIA");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NTTObjectIdentifiers.id_camellia256_cbc, "CAMELLIA");
         var1.addAlgorithm("Cipher.CAMELLIA", PREFIX + "$ECB");
         var1.addAlgorithm("Cipher." + NTTObjectIdentifiers.id_camellia128_cbc, PREFIX + "$CBC");
         var1.addAlgorithm("Cipher." + NTTObjectIdentifiers.id_camellia192_cbc, PREFIX + "$CBC");
         var1.addAlgorithm("Cipher." + NTTObjectIdentifiers.id_camellia256_cbc, PREFIX + "$CBC");
         var1.addAlgorithm("Cipher.CAMELLIARFC3211WRAP", PREFIX + "$RFC3211Wrap");
         var1.addAlgorithm("Cipher.CAMELLIAWRAP", PREFIX + "$Wrap");
         var1.addAlgorithm("Alg.Alias.Cipher." + NTTObjectIdentifiers.id_camellia128_wrap, "CAMELLIAWRAP");
         var1.addAlgorithm("Alg.Alias.Cipher." + NTTObjectIdentifiers.id_camellia192_wrap, "CAMELLIAWRAP");
         var1.addAlgorithm("Alg.Alias.Cipher." + NTTObjectIdentifiers.id_camellia256_wrap, "CAMELLIAWRAP");
         var1.addAlgorithm("KeyGenerator.CAMELLIA", PREFIX + "$KeyGen");
         var1.addAlgorithm("KeyGenerator." + NTTObjectIdentifiers.id_camellia128_wrap, PREFIX + "$KeyGen128");
         var1.addAlgorithm("KeyGenerator." + NTTObjectIdentifiers.id_camellia192_wrap, PREFIX + "$KeyGen192");
         var1.addAlgorithm("KeyGenerator." + NTTObjectIdentifiers.id_camellia256_wrap, PREFIX + "$KeyGen256");
         var1.addAlgorithm("KeyGenerator." + NTTObjectIdentifiers.id_camellia128_cbc, PREFIX + "$KeyGen128");
         var1.addAlgorithm("KeyGenerator." + NTTObjectIdentifiers.id_camellia192_cbc, PREFIX + "$KeyGen192");
         var1.addAlgorithm("KeyGenerator." + NTTObjectIdentifiers.id_camellia256_cbc, PREFIX + "$KeyGen256");
      }
   }

   public static class RFC3211Wrap extends BaseWrapCipher {
      public RFC3211Wrap() {
         super(new RFC3211WrapEngine(new CamelliaEngine()), 16);
      }
   }

   public static class Wrap extends BaseWrapCipher {
      public Wrap() {
         super(new CamelliaWrapEngine());
      }
   }
}
