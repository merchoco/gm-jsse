package org.bc.jcajce.provider.digest;

import org.bc.asn1.iana.IANAObjectIdentifiers;
import org.bc.asn1.oiw.OIWObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class SHA1 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new SHA1Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         SHA1.Digest var1 = (SHA1.Digest)super.clone();
         var1.digest = new SHA1Digest((SHA1Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new SHA1Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACSHA1", 160, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = SHA1.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.SHA-1", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest.SHA1", "SHA-1");
         var1.addAlgorithm("Alg.Alias.MessageDigest.SHA", "SHA-1");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + OIWObjectIdentifiers.idSHA1, "SHA-1");
         this.addHMACAlgorithm(var1, "SHA1", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
         this.addHMACAlias(var1, "SHA1", PKCSObjectIdentifiers.id_hmacWithSHA1);
         this.addHMACAlias(var1, "SHA1", IANAObjectIdentifiers.hmacSHA1);
      }
   }
}
