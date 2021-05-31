package org.bc.jcajce.provider.digest;

import org.bc.asn1.iana.IANAObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.TigerDigest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class Tiger {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new TigerDigest());
      }

      public Object clone() throws CloneNotSupportedException {
         Tiger.Digest var1 = (Tiger.Digest)super.clone();
         var1.digest = new TigerDigest((TigerDigest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new TigerDigest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACTIGER", 192, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = Tiger.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.TIGER", PREFIX + "$Digest");
         var1.addAlgorithm("MessageDigest.Tiger", PREFIX + "$Digest");
         this.addHMACAlgorithm(var1, "TIGER", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
         this.addHMACAlias(var1, "TIGER", IANAObjectIdentifiers.hmacTIGER);
      }
   }
}
