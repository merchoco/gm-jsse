package org.bc.jcajce.provider.asymmetric;

import org.bc.asn1.oiw.OIWObjectIdentifiers;
import org.bc.jcajce.provider.asymmetric.elgamal.KeyFactorySpi;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class ElGamal {
   private static final String PREFIX = "org.bc.jcajce.provider.asymmetric.elgamal.";

   public static class Mappings extends AsymmetricAlgorithmProvider {
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("AlgorithmParameterGenerator.ELGAMAL", "org.bc.jcajce.provider.asymmetric.elgamal.AlgorithmParameterGeneratorSpi");
         var1.addAlgorithm("AlgorithmParameterGenerator.ElGamal", "org.bc.jcajce.provider.asymmetric.elgamal.AlgorithmParameterGeneratorSpi");
         var1.addAlgorithm("AlgorithmParameters.ELGAMAL", "org.bc.jcajce.provider.asymmetric.elgamal.AlgorithmParametersSpi");
         var1.addAlgorithm("AlgorithmParameters.ElGamal", "org.bc.jcajce.provider.asymmetric.elgamal.AlgorithmParametersSpi");
         var1.addAlgorithm("Cipher.ELGAMAL", "org.bc.jcajce.provider.asymmetric.elgamal.CipherSpi$NoPadding");
         var1.addAlgorithm("Cipher.ElGamal", "org.bc.jcajce.provider.asymmetric.elgamal.CipherSpi$NoPadding");
         var1.addAlgorithm("Alg.Alias.Cipher.ELGAMAL/ECB/PKCS1PADDING", "ELGAMAL/PKCS1");
         var1.addAlgorithm("Alg.Alias.Cipher.ELGAMAL/NONE/PKCS1PADDING", "ELGAMAL/PKCS1");
         var1.addAlgorithm("Alg.Alias.Cipher.ELGAMAL/NONE/NOPADDING", "ELGAMAL");
         var1.addAlgorithm("Cipher.ELGAMAL/PKCS1", "org.bc.jcajce.provider.asymmetric.elgamal.CipherSpi$PKCS1v1_5Padding");
         var1.addAlgorithm("KeyFactory.ELGAMAL", "org.bc.jcajce.provider.asymmetric.elgamal.KeyFactorySpi");
         var1.addAlgorithm("KeyFactory.ElGamal", "org.bc.jcajce.provider.asymmetric.elgamal.KeyFactorySpi");
         var1.addAlgorithm("KeyPairGenerator.ELGAMAL", "org.bc.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi");
         var1.addAlgorithm("KeyPairGenerator.ElGamal", "org.bc.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi");
         KeyFactorySpi var2 = new KeyFactorySpi();
         this.registerOid(var1, OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL", var2);
         this.registerOidAlgorithmParameters(var1, OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL");
      }
   }
}
