package org.bc.jcajce.provider.digest;

import org.bc.asn1.iana.IANAObjectIdentifiers;
import org.bc.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.RIPEMD160Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class RIPEMD160 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new RIPEMD160Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         RIPEMD160.Digest var1 = (RIPEMD160.Digest)super.clone();
         var1.digest = new RIPEMD160Digest((RIPEMD160Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new RIPEMD160Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACRIPEMD160", 160, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = RIPEMD160.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.RIPEMD160", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
         this.addHMACAlgorithm(var1, "RIPEMD160", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
         this.addHMACAlias(var1, "RIPEMD160", IANAObjectIdentifiers.hmacRIPEMD160);
      }
   }
}
