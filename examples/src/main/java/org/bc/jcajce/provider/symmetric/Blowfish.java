package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.BlowfishEngine;
import org.bc.crypto.modes.CBCBlockCipher;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class Blowfish {
   public static class AlgParams extends IvAlgorithmParameters {
      protected String engineToString() {
         return "Blowfish IV";
      }
   }

   public static class CBC extends BaseBlockCipher {
      public CBC() {
         super((BlockCipher)(new CBCBlockCipher(new BlowfishEngine())), 64);
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new BlowfishEngine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("Blowfish", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = Blowfish.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.BLOWFISH", PREFIX + "$ECB");
         var1.addAlgorithm("Cipher.1.3.6.1.4.1.3029.1.2", PREFIX + "$CBC");
         var1.addAlgorithm("KeyGenerator.BLOWFISH", PREFIX + "$KeyGen");
         var1.addAlgorithm("Alg.Alias.KeyGenerator.1.3.6.1.4.1.3029.1.2", "BLOWFISH");
         var1.addAlgorithm("AlgorithmParameters.BLOWFISH", PREFIX + "$AlgParams");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.1.3.6.1.4.1.3029.1.2", "BLOWFISH");
      }
   }
}
