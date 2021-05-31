package org.bc.jcajce.provider.digest;

import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.SHA512Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class SHA512 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new SHA512Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         SHA512.Digest var1 = (SHA512.Digest)super.clone();
         var1.digest = new SHA512Digest((SHA512Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new SHA512Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACSHA512", 512, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = SHA512.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.SHA-512", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest.SHA512", "SHA-512");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers.id_sha512, "SHA-512");
         this.addHMACAlgorithm(var1, "SHA512", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
         this.addHMACAlias(var1, "SHA512", PKCSObjectIdentifiers.id_hmacWithSHA512);
      }
   }
}
