package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.TwofishEngine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class Twofish {
   public static class AlgParams extends IvAlgorithmParameters {
      protected String engineToString() {
         return "Twofish IV";
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new TwofishEngine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("Twofish", 256, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = Twofish.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.Twofish", PREFIX + "$ECB");
         var1.addAlgorithm("KeyGenerator.Twofish", PREFIX + "$KeyGen");
         var1.addAlgorithm("AlgorithmParameters.Twofish", PREFIX + "$AlgParams");
      }
   }
}
