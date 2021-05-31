package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.engines.Salsa20Engine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class Salsa20 {
   public static class Base extends BaseStreamCipher {
      public Base() {
         super((StreamCipher)(new Salsa20Engine()), 8);
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("Salsa20", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = Salsa20.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.SALSA20", PREFIX + "$Base");
         var1.addAlgorithm("KeyGenerator.SALSA20", PREFIX + "$KeyGen");
      }
   }
}
