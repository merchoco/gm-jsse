package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.TEAEngine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class TEA {
   public static class AlgParams extends IvAlgorithmParameters {
      protected String engineToString() {
         return "TEA IV";
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new TEAEngine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("TEA", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = TEA.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.TEA", PREFIX + "$ECB");
         var1.addAlgorithm("KeyGenerator.TEA", PREFIX + "$KeyGen");
         var1.addAlgorithm("AlgorithmParameters.TEA", PREFIX + "$AlgParams");
      }
   }
}
