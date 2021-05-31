package org.bc.jcajce.provider.digest;

import org.bc.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.RIPEMD128Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class RIPEMD128 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new RIPEMD128Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         RIPEMD128.Digest var1 = (RIPEMD128.Digest)super.clone();
         var1.digest = new RIPEMD128Digest((RIPEMD128Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new RIPEMD128Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACRIPEMD128", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = RIPEMD128.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.RIPEMD128", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
         this.addHMACAlgorithm(var1, "RIPEMD128", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
      }
   }
}
