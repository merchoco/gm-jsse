package org.bc.pqc.jcajce.provider;

import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bc.pqc.asn1.PQCObjectIdentifiers;
import org.bc.pqc.jcajce.provider.rainbow.RainbowKeyFactorySpi;

public class Rainbow {
   private static final String PREFIX = "org.bc.pqc.jcajce.provider.rainbow.";

   public static class Mappings extends AsymmetricAlgorithmProvider {
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("KeyFactory.Rainbow", "org.bc.pqc.jcajce.provider.rainbow.RainbowKeyFactorySpi");
         var1.addAlgorithm("KeyPairGenerator.Rainbow", "org.bc.pqc.jcajce.provider.rainbow.RainbowKeyPairGeneratorSpi");
         this.addSignatureAlgorithm(var1, "SHA224", "Rainbow", "org.bc.pqc.jcajce.provider.rainbow.SignatureSpi$withSha224", PQCObjectIdentifiers.rainbowWithSha224);
         this.addSignatureAlgorithm(var1, "SHA256", "Rainbow", "org.bc.pqc.jcajce.provider.rainbow.SignatureSpi$withSha256", PQCObjectIdentifiers.rainbowWithSha256);
         this.addSignatureAlgorithm(var1, "SHA384", "Rainbow", "org.bc.pqc.jcajce.provider.rainbow.SignatureSpi$withSha384", PQCObjectIdentifiers.rainbowWithSha384);
         this.addSignatureAlgorithm(var1, "SHA512", "Rainbow", "org.bc.pqc.jcajce.provider.rainbow.SignatureSpi$withSha512", PQCObjectIdentifiers.rainbowWithSha512);
         RainbowKeyFactorySpi var2 = new RainbowKeyFactorySpi();
         this.registerOid(var1, PQCObjectIdentifiers.rainbow, "Rainbow", var2);
         this.registerOidAlgorithmParameters(var1, PQCObjectIdentifiers.rainbow, "Rainbow");
      }
   }
}
