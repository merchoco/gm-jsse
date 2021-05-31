package org.bc.jcajce.provider.digest;

import org.bc.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.GOST3411Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class GOST3411 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new GOST3411Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         GOST3411.Digest var1 = (GOST3411.Digest)super.clone();
         var1.digest = new GOST3411Digest((GOST3411Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new GOST3411Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACGOST3411", 256, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = GOST3411.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.GOST3411", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest.GOST", "GOST3411");
         var1.addAlgorithm("Alg.Alias.MessageDigest.GOST-3411", "GOST3411");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + CryptoProObjectIdentifiers.gostR3411, "GOST3411");
         this.addHMACAlgorithm(var1, "GOST3411", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
         this.addHMACAlias(var1, "GOST3411", CryptoProObjectIdentifiers.gostR3411);
      }
   }
}
