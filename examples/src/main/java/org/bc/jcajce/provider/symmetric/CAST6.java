package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.CAST6Engine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class CAST6 {
   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new CAST6Engine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("CAST6", 256, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = CAST6.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.CAST6", PREFIX + "$ECB");
         var1.addAlgorithm("KeyGenerator.CAST6", PREFIX + "$KeyGen");
      }
   }
}
