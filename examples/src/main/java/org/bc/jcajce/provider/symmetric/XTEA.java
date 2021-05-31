package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.XTEAEngine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class XTEA {
   public static class AlgParams extends IvAlgorithmParameters {
      protected String engineToString() {
         return "XTEA IV";
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new XTEAEngine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("XTEA", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = XTEA.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.XTEA", PREFIX + "$ECB");
         var1.addAlgorithm("KeyGenerator.XTEA", PREFIX + "$KeyGen");
         var1.addAlgorithm("AlgorithmParameters.XTEA", PREFIX + "$AlgParams");
      }
   }
}
