package org.bc.jcajce.provider.digest;

import org.bc.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.RIPEMD256Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class RIPEMD256 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new RIPEMD256Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         RIPEMD256.Digest var1 = (RIPEMD256.Digest)super.clone();
         var1.digest = new RIPEMD256Digest((RIPEMD256Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new RIPEMD256Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACRIPEMD256", 256, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = RIPEMD256.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.RIPEMD256", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");
         this.addHMACAlgorithm(var1, "RIPEMD256", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
      }
   }
}
