package org.bc.jcajce.provider.digest;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.WhirlpoolDigest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class Whirlpool {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new WhirlpoolDigest());
      }

      public Object clone() throws CloneNotSupportedException {
         Whirlpool.Digest var1 = (Whirlpool.Digest)super.clone();
         var1.digest = new WhirlpoolDigest((WhirlpoolDigest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new WhirlpoolDigest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACWHIRLPOOL", 512, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = Whirlpool.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.WHIRLPOOL", PREFIX + "$Digest");
         this.addHMACAlgorithm(var1, "WHIRLPOOL", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
      }
   }
}
