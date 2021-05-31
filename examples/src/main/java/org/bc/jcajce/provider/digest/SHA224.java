package org.bc.jcajce.provider.digest;

import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.SHA224Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class SHA224 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new SHA224Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         SHA224.Digest var1 = (SHA224.Digest)super.clone();
         var1.digest = new SHA224Digest((SHA224Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new SHA224Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACSHA224", 224, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = SHA224.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.SHA-224", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest.SHA224", "SHA-224");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + NISTObjectIdentifiers.id_sha224, "SHA-224");
         this.addHMACAlgorithm(var1, "SHA224", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
         this.addHMACAlias(var1, "SHA224", PKCSObjectIdentifiers.id_hmacWithSHA224);
      }
   }
}
