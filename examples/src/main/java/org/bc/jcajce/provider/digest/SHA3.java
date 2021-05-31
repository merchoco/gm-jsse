package org.bc.jcajce.provider.digest;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.SHA3Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class SHA3 {
   public static class Digest224 extends SHA3.DigestSHA3 {
      public Digest224() {
         super(224);
      }
   }

   public static class Digest256 extends SHA3.DigestSHA3 {
      public Digest256() {
         super(256);
      }
   }

   public static class Digest384 extends SHA3.DigestSHA3 {
      public Digest384() {
         super(384);
      }
   }

   public static class Digest512 extends SHA3.DigestSHA3 {
      public Digest512() {
         super(512);
      }
   }

   public static class DigestSHA3 extends BCMessageDigest implements Cloneable {
      public DigestSHA3(int var1) {
         super(new SHA3Digest(var1));
      }

      public Object clone() throws CloneNotSupportedException {
         BCMessageDigest var1 = (BCMessageDigest)super.clone();
         var1.digest = new SHA3Digest((SHA3Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac224 extends JCEMac {
      public HashMac224() {
         super(new HMac(new SHA3Digest(224)));
      }
   }

   public static class HashMac256 extends JCEMac {
      public HashMac256() {
         super(new HMac(new SHA3Digest(256)));
      }
   }

   public static class HashMac384 extends JCEMac {
      public HashMac384() {
         super(new HMac(new SHA3Digest(384)));
      }
   }

   public static class HashMac512 extends JCEMac {
      public HashMac512() {
         super(new HMac(new SHA3Digest(512)));
      }
   }

   public static class KeyGenerator224 extends BaseKeyGenerator {
      public KeyGenerator224() {
         super("HMACSHA3-224", 224, new CipherKeyGenerator());
      }
   }

   public static class KeyGenerator256 extends BaseKeyGenerator {
      public KeyGenerator256() {
         super("HMACSHA3-256", 256, new CipherKeyGenerator());
      }
   }

   public static class KeyGenerator384 extends BaseKeyGenerator {
      public KeyGenerator384() {
         super("HMACSHA3-384", 384, new CipherKeyGenerator());
      }
   }

   public static class KeyGenerator512 extends BaseKeyGenerator {
      public KeyGenerator512() {
         super("HMACSHA3-512", 512, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = SHA3.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.SHA3-224", PREFIX + "$Digest224");
         var1.addAlgorithm("MessageDigest.SHA3-256", PREFIX + "$Digest256");
         var1.addAlgorithm("MessageDigest.SHA3-384", PREFIX + "$Digest384");
         var1.addAlgorithm("MessageDigest.SHA3-512", PREFIX + "$Digest512");
         this.addHMACAlgorithm(var1, "SHA3-224", PREFIX + "$HashMac224", PREFIX + "$KeyGenerator224");
         this.addHMACAlgorithm(var1, "SHA3-256", PREFIX + "$HashMac256", PREFIX + "$KeyGenerator256");
         this.addHMACAlgorithm(var1, "SHA3-384", PREFIX + "$HashMac384", PREFIX + "$KeyGenerator384");
         this.addHMACAlgorithm(var1, "SHA3-512", PREFIX + "$HashMac512", PREFIX + "$KeyGenerator512");
      }
   }
}
