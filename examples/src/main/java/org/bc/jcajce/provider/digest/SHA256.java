package org.bc.jcajce.provider.digest;

import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class SHA256 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new SHA256Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         SHA256.Digest var1 = (SHA256.Digest)super.clone();
         var1.digest = new SHA256Digest((SHA256Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new SHA256Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACSHA256", 256, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = SHA256.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.SHA-256", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest.SHA256", "SHA-256");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers.id_sha256, "SHA-256");
         this.addHMACAlgorithm(var1, "SHA256", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
         this.addHMACAlias(var1, "SHA256", PKCSObjectIdentifiers.id_hmacWithSHA256);
      }
   }
}
