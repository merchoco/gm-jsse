package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.engines.Grainv1Engine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class Grainv1 {
   public static class Base extends BaseStreamCipher {
      public Base() {
         super((StreamCipher)(new Grainv1Engine()), 8);
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("Grainv1", 80, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = Grainv1.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.Grainv1", PREFIX + "$Base");
         var1.addAlgorithm("KeyGenerator.Grainv1", PREFIX + "$KeyGen");
      }
   }
}
