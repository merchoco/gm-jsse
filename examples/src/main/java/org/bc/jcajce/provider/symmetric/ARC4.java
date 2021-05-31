package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.engines.RC4Engine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class ARC4 {
   public static class Base extends BaseStreamCipher {
      public Base() {
         super((StreamCipher)(new RC4Engine()), 0);
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("RC4", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = ARC4.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.ARC4", PREFIX + "$Base");
         var1.addAlgorithm("Alg.Alias.Cipher.1.2.840.113549.3.4", "ARC4");
         var1.addAlgorithm("Alg.Alias.Cipher.ARCFOUR", "ARC4");
         var1.addAlgorithm("Alg.Alias.Cipher.RC4", "ARC4");
         var1.addAlgorithm("KeyGenerator.ARC4", PREFIX + "$KeyGen");
         var1.addAlgorithm("Alg.Alias.KeyGenerator.RC4", "ARC4");
         var1.addAlgorithm("Alg.Alias.KeyGenerator.1.2.840.113549.3.4", "ARC4");
      }
   }
}
