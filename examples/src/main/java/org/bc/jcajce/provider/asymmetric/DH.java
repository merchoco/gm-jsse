package org.bc.jcajce.provider.asymmetric;

import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class DH {
   private static final String PREFIX = "org.bc.jcajce.provider.asymmetric.dh.";

   public static class Mappings extends AsymmetricAlgorithmProvider {
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("KeyPairGenerator.DH", "org.bc.jcajce.provider.asymmetric.dh.KeyPairGeneratorSpi");
         var1.addAlgorithm("Alg.Alias.KeyPairGenerator.DIFFIEHELLMAN", "DH");
         var1.addAlgorithm("KeyAgreement.DH", "org.bc.jcajce.provider.asymmetric.dh.KeyAgreementSpi");
         var1.addAlgorithm("Alg.Alias.KeyAgreement.DIFFIEHELLMAN", "DH");
         var1.addAlgorithm("KeyFactory.DH", "org.bc.jcajce.provider.asymmetric.dh.KeyFactorySpi");
         var1.addAlgorithm("Alg.Alias.KeyFactory.DIFFIEHELLMAN", "DH");
         var1.addAlgorithm("AlgorithmParameters.DH", "org.bc.jcajce.provider.asymmetric.dh.AlgorithmParametersSpi");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.DIFFIEHELLMAN", "DH");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.DIFFIEHELLMAN", "DH");
         var1.addAlgorithm("AlgorithmParameterGenerator.DH", "org.bc.jcajce.provider.asymmetric.dh.AlgorithmParameterGeneratorSpi");
         var1.addAlgorithm("Cipher.DHIES", "org.bc.jcajce.provider.asymmetric.dh.IESCipher$IES");
         var1.addAlgorithm("Cipher.DHIESwithAES", "org.bc.jcajce.provider.asymmetric.dh.IESCipher$IESwithAES");
         var1.addAlgorithm("Cipher.DHIESWITHAES", "org.bc.jcajce.provider.asymmetric.dh.IESCipher$IESwithAES");
         var1.addAlgorithm("Cipher.DHIESWITHDESEDE", "org.bc.jcajce.provider.asymmetric.dh.IESCipher$IESwithDESede");
         var1.addAlgorithm("KeyPairGenerator.IES", "org.bc.jcajce.provider.asymmetric.dh.KeyPairGeneratorSpi");
      }
   }
}
