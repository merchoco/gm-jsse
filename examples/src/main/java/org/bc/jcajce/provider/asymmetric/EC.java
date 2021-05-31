package org.bc.jcajce.provider.asymmetric;

import org.bc.asn1.eac.EACObjectIdentifiers;
import org.bc.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class EC {
   private static final String PREFIX = "org.bc.jcajce.provider.asymmetric.ec.";

   public static class Mappings extends AsymmetricAlgorithmProvider {
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("KeyAgreement.ECDH", "org.bc.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DH");
         var1.addAlgorithm("KeyAgreement.ECDHC", "org.bc.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHC");
         var1.addAlgorithm("KeyAgreement.ECMQV", "org.bc.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQV");
         var1.addAlgorithm("KeyAgreement." + X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "org.bc.jcajce.provider.asymmetric.ec.KeyAgreementSpi$DHwithSHA1KDF");
         var1.addAlgorithm("KeyAgreement." + X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "org.bc.jcajce.provider.asymmetric.ec.KeyAgreementSpi$MQVwithSHA1KDF");
         this.registerOid(var1, X9ObjectIdentifiers.id_ecPublicKey, "EC", new KeyFactorySpi.EC());
         this.registerOid(var1, X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC", new KeyFactorySpi.EC());
         this.registerOid(var1, X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "ECMQV", new KeyFactorySpi.ECMQV());
         this.registerOidAlgorithmParameters(var1, X9ObjectIdentifiers.id_ecPublicKey, "EC");
         this.registerOidAlgorithmParameters(var1, X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC");
         this.registerOidAlgorithmParameters(var1, X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "EC");
         var1.addAlgorithm("KeyFactory.EC", "org.bc.jcajce.provider.asymmetric.ec.KeyFactorySpi$EC");
         var1.addAlgorithm("KeyFactory.ECDSA", "org.bc.jcajce.provider.asymmetric.ec.KeyFactorySpi$ECDSA");
         var1.addAlgorithm("KeyFactory.ECDH", "org.bc.jcajce.provider.asymmetric.ec.KeyFactorySpi$ECDH");
         var1.addAlgorithm("KeyFactory.ECDHC", "org.bc.jcajce.provider.asymmetric.ec.KeyFactorySpi$ECDHC");
         var1.addAlgorithm("KeyFactory.ECMQV", "org.bc.jcajce.provider.asymmetric.ec.KeyFactorySpi$ECMQV");
         var1.addAlgorithm("KeyPairGenerator.EC", "org.bc.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$EC");
         var1.addAlgorithm("KeyPairGenerator.ECDSA", "org.bc.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDSA");
         var1.addAlgorithm("KeyPairGenerator.ECDH", "org.bc.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDH");
         var1.addAlgorithm("KeyPairGenerator.ECDHC", "org.bc.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDHC");
         var1.addAlgorithm("KeyPairGenerator.ECIES", "org.bc.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDH");
         var1.addAlgorithm("KeyPairGenerator.ECMQV", "org.bc.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECMQV");
         var1.addAlgorithm("Cipher.ECIES", "org.bc.jcajce.provider.asymmetric.ec.IESCipher$ECIES");
         var1.addAlgorithm("Cipher.ECIESwithAES", "org.bc.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithAES");
         var1.addAlgorithm("Cipher.ECIESWITHAES", "org.bc.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithAES");
         var1.addAlgorithm("Cipher.ECIESwithDESEDE", "org.bc.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithDESede");
         var1.addAlgorithm("Cipher.ECIESWITHDESEDE", "org.bc.jcajce.provider.asymmetric.ec.IESCipher$ECIESwithDESede");
         var1.addAlgorithm("Signature.ECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA");
         var1.addAlgorithm("Signature.NONEwithECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSAnone");
         var1.addAlgorithm("Alg.Alias.Signature.SHA1withECDSA", "ECDSA");
         var1.addAlgorithm("Alg.Alias.Signature.ECDSAwithSHA1", "ECDSA");
         var1.addAlgorithm("Alg.Alias.Signature.SHA1WITHECDSA", "ECDSA");
         var1.addAlgorithm("Alg.Alias.Signature.ECDSAWITHSHA1", "ECDSA");
         var1.addAlgorithm("Alg.Alias.Signature.SHA1WithECDSA", "ECDSA");
         var1.addAlgorithm("Alg.Alias.Signature.ECDSAWithSHA1", "ECDSA");
         var1.addAlgorithm("Alg.Alias.Signature.1.2.840.10045.4.1", "ECDSA");
         var1.addAlgorithm("Alg.Alias.Signature." + TeleTrusTObjectIdentifiers.ecSignWithSha1, "ECDSA");
         this.addSignatureAlgorithm(var1, "SHA224", "ECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA224", X9ObjectIdentifiers.ecdsa_with_SHA224);
         this.addSignatureAlgorithm(var1, "SHA256", "ECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA256", X9ObjectIdentifiers.ecdsa_with_SHA256);
         this.addSignatureAlgorithm(var1, "SHA384", "ECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA384", X9ObjectIdentifiers.ecdsa_with_SHA384);
         this.addSignatureAlgorithm(var1, "SHA512", "ECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSA512", X9ObjectIdentifiers.ecdsa_with_SHA512);
         this.addSignatureAlgorithm(var1, "RIPEMD160", "ECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecDSARipeMD160", TeleTrusTObjectIdentifiers.ecSignWithRipemd160);
         var1.addAlgorithm("Signature.SHA1WITHECNR", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR");
         var1.addAlgorithm("Signature.SHA224WITHECNR", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR224");
         var1.addAlgorithm("Signature.SHA256WITHECNR", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR256");
         var1.addAlgorithm("Signature.SHA384WITHECNR", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR384");
         var1.addAlgorithm("Signature.SHA512WITHECNR", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecNR512");
         this.addSignatureAlgorithm(var1, "SHA1", "CVC-ECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
         this.addSignatureAlgorithm(var1, "SHA224", "CVC-ECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA224", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
         this.addSignatureAlgorithm(var1, "SHA256", "CVC-ECDSA", "org.bc.jcajce.provider.asymmetric.ec.SignatureSpi$ecCVCDSA256", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
      }
   }
}
