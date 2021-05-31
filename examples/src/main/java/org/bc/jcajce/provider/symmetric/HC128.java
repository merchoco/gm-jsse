package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.engines.HC128Engine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class HC128 {
   public static class Base extends BaseStreamCipher {
      public Base() {
         super((StreamCipher)(new HC128Engine()), 16);
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("HC128", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = HC128.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.HC128", PREFIX + "$Base");
         var1.addAlgorithm("KeyGenerator.HC128", PREFIX + "$KeyGen");
      }
   }
}
