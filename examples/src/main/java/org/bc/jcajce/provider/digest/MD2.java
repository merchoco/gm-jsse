package org.bc.jcajce.provider.digest;

import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.digests.MD2Digest;
import org.bc.crypto.macs.HMac;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jce.provider.JCEMac;

public class MD2 {
   public static class Digest extends BCMessageDigest implements Cloneable {
      public Digest() {
         super(new MD2Digest());
      }

      public Object clone() throws CloneNotSupportedException {
         MD2.Digest var1 = (MD2.Digest)super.clone();
         var1.digest = new MD2Digest((MD2Digest)this.digest);
         return var1;
      }
   }

   public static class HashMac extends JCEMac {
      public HashMac() {
         super(new HMac(new MD2Digest()));
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("HMACMD2", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends DigestAlgorithmProvider {
      private static final String PREFIX = MD2.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("MessageDigest.MD2", PREFIX + "$Digest");
         var1.addAlgorithm("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers.md2, "MD2");
         this.addHMACAlgorithm(var1, "MD2", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
      }
   }
}
