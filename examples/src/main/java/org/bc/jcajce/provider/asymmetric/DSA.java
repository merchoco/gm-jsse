package org.bc.jcajce.provider.asymmetric;

import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bc.jcajce.provider.asymmetric.dsa.KeyFactorySpi;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class DSA {
   private static final String PREFIX = "org.bc.jcajce.provider.asymmetric.dsa.";

   public static class Mappings extends AsymmetricAlgorithmProvider {
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("AlgorithmParameters.DSA", "org.bc.jcajce.provider.asymmetric.dsa.AlgorithmParametersSpi");
         var1.addAlgorithm("AlgorithmParameterGenerator.DSA", "org.bc.jcajce.provider.asymmetric.dsa.AlgorithmParameterGeneratorSpi");
         var1.addAlgorithm("KeyPairGenerator.DSA", "org.bc.jcajce.provider.asymmetric.dsa.KeyPairGeneratorSpi");
         var1.addAlgorithm("KeyFactory.DSA", "org.bc.jcajce.provider.asymmetric.dsa.KeyFactorySpi");
         var1.addAlgorithm("Signature.DSA", "org.bc.jcajce.provider.asymmetric.dsa.DSASigner$stdDSA");
         var1.addAlgorithm("Signature.NONEWITHDSA", "org.bc.jcajce.provider.asymmetric.dsa.DSASigner$noneDSA");
         var1.addAlgorithm("Alg.Alias.Signature.RAWDSA", "NONEWITHDSA");
         this.addSignatureAlgorithm(var1, "SHA224", "DSA", "org.bc.jcajce.provider.asymmetric.dsa.DSASigner$dsa224", NISTObjectIdentifiers.dsa_with_sha224);
         this.addSignatureAlgorithm(var1, "SHA256", "DSA", "org.bc.jcajce.provider.asymmetric.dsa.DSASigner$dsa256", NISTObjectIdentifiers.dsa_with_sha256);
         this.addSignatureAlgorithm(var1, "SHA384", "DSA", "org.bc.jcajce.provider.asymmetric.dsa.DSASigner$dsa384", NISTObjectIdentifiers.dsa_with_sha384);
         this.addSignatureAlgorithm(var1, "SHA512", "DSA", "org.bc.jcajce.provider.asymmetric.dsa.DSASigner$dsa512", NISTObjectIdentifiers.dsa_with_sha512);
         var1.addAlgorithm("Alg.Alias.Signature.SHA/DSA", "DSA");
         var1.addAlgorithm("Alg.Alias.Signature.SHA1withDSA", "DSA");
         var1.addAlgorithm("Alg.Alias.Signature.SHA1WITHDSA", "DSA");
         var1.addAlgorithm("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.1", "DSA");
         var1.addAlgorithm("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.3", "DSA");
         var1.addAlgorithm("Alg.Alias.Signature.DSAwithSHA1", "DSA");
         var1.addAlgorithm("Alg.Alias.Signature.DSAWITHSHA1", "DSA");
         var1.addAlgorithm("Alg.Alias.Signature.SHA1WithDSA", "DSA");
         var1.addAlgorithm("Alg.Alias.Signature.DSAWithSHA1", "DSA");
         var1.addAlgorithm("Alg.Alias.Signature.1.2.840.10040.4.3", "DSA");
         KeyFactorySpi var2 = new KeyFactorySpi();

         for(int var3 = 0; var3 != DSAUtil.dsaOids.length; ++var3) {
            var1.addAlgorithm("Alg.Alias.Signature." + DSAUtil.dsaOids[var3], "DSA");
            this.registerOid(var1, DSAUtil.dsaOids[var3], "DSA", var2);
            this.registerOidAlgorithmParameters(var1, DSAUtil.dsaOids[var3], "DSA");
         }

      }
   }
}
