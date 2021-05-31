package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.SerpentEngine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class Serpent {
   public static class AlgParams extends IvAlgorithmParameters {
      protected String engineToString() {
         return "Serpent IV";
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new SerpentEngine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("Serpent", 192, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = Serpent.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.Serpent", PREFIX + "$ECB");
         var1.addAlgorithm("KeyGenerator.Serpent", PREFIX + "$KeyGen");
         var1.addAlgorithm("AlgorithmParameters.Serpent", PREFIX + "$AlgParams");
      }
   }
}
