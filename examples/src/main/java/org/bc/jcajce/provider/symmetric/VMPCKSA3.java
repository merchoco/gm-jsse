package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.engines.VMPCKSA3Engine;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class VMPCKSA3 {
   public static class Base extends BaseStreamCipher {
      public Base() {
         super((StreamCipher)(new VMPCKSA3Engine()), 16);
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("VMPC-KSA3", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = VMPCKSA3.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.VMPC-KSA3", PREFIX + "$Base");
         var1.addAlgorithm("KeyGenerator.VMPC-KSA3", PREFIX + "$KeyGen");
      }
   }
}
