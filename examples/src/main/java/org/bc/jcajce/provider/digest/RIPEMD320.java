package org.bc.jcajce.provider.digest;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.RIPEMD320Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class RIPEMD320 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new RIPEMD320Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         RIPEMD320.Digest var1 = (RIPEMD320.Digest)super.clone();
         var1.digest = new RIPEMD320Digest((RIPEMD320Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new RIPEMD320Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACRIPEMD320", 320, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = RIPEMD320.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.RIPEMD320", PREFIX + "$Digest");
         this.addHMACAlgorithm(var1, "RIPEMD320", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
      }
   }
}
