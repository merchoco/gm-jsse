package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.RijndaelEngine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class Rijndael {
   public static class AlgParams extends IvAlgorithmParameters {
      protected String engineToString() {
         return "Rijndael IV";
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new RijndaelEngine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("Rijndael", 192, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = Rijndael.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.RIJNDAEL", PREFIX + "$ECB");
         var1.addAlgorithm("KeyGenerator.RIJNDAEL", PREFIX + "$KeyGen");
         var1.addAlgorithm("AlgorithmParameters.RIJNDAEL", PREFIX + "$AlgParams");
      }
   }
}
