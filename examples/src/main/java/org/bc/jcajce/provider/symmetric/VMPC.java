package org.bc.jcajce.provider.symmetric;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.engines.VMPCEngine;
import org.bc.crypto.macs.VMPCMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseMac;
import org.bc.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bc.jcajce.provider.util.AlgorithmProvider;

public final class VMPC {
   public static class Base extends BaseStreamCipher {
      public Base() {
         super((StreamCipher)(new VMPCEngine()), 16);
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("VMPC", 128, new CipherKeyGenerator());
      }
   }

   public static class Mac extends BaseMac {
      public Mac() {
         super(new VMPCMac());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = VMPC.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.VMPC", PREFIX + "$Base");
         var1.addAlgorithm("KeyGenerator.VMPC", PREFIX + "$KeyGen");
         var1.addAlgorithm("Mac.VMPCMAC", PREFIX + "$Mac");
         var1.addAlgorithm("Alg.Alias.Mac.VMPC", "VMPCMAC");
         var1.addAlgorithm("Alg.Alias.Mac.VMPC-MAC", "VMPCMAC");
      }
   }
}
