package org.bc.jcajce.provider.digest;

import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.SHA384Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class SHA384 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new SHA384Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         SHA384.Digest var1 = (SHA384.Digest)super.clone();
         var1.digest = new SHA384Digest((SHA384Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new SHA384Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACSHA384", 384, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = SHA384.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.SHA-384", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest.SHA384", "SHA-384");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers.id_sha384, "SHA-384");
         this.addHMACAlgorithm(var1, "SHA384", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
         this.addHMACAlias(var1, "SHA384", PKCSObjectIdentifiers.id_hmacWithSHA384);
      }
   }
}
